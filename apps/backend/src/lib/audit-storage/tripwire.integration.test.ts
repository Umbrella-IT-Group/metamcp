/**
 * The one claim no unit test can make: a real crossing, against a real
 * database, ends up as a row the operator can find in the History view.
 *
 * Every layer between the tripwire and that row is stubbed somewhere else:
 * the stats source in `tripwire.test.ts`, the repository in
 * `lib/gateway-events/sink.test.ts`. All of those suites would stay green
 * if the lazy repository import resolved to nothing in a real process, or if
 * the `system` category were filtered out on the way to the table. The whole
 * design rests on the monitor reporting through the surface it monitors, and
 * this is the case that proves it does.
 *
 * Opt in with TEST_DATABASE_URL:
 *
 *   docker run -d --name metamcp-audit-storage-test -e POSTGRES_PASSWORD=test \
 *     -e POSTGRES_USER=test -e POSTGRES_DB=metamcp_test \
 *     -p 127.0.0.1:55521:5432 postgres:16-alpine
 *   cd apps/backend
 *   DATABASE_URL=postgres://test:test@127.0.0.1:55521/metamcp_test \
 *     npx drizzle-kit migrate
 *   TEST_DATABASE_URL=postgres://test:test@127.0.0.1:55521/metamcp_test \
 *     npx vitest run src/lib/audit-storage/tripwire.integration.test.ts
 *
 * The rows it writes are inside `gateway_events`' 30-day immutability window
 * and cannot be cleaned up afterwards. Point it at a disposable database.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;

const describeIfDb = describe.skipIf(!TEST_DATABASE_URL);

type Db = Awaited<typeof import("@/db/index")>["db"];

let db: Db;
let checkAuditStorage: (typeof import("./tripwire"))["checkAuditStorage"];

/** Poll for the detached history write rather than the call that scheduled it. */
async function tripwireMessages(): Promise<string[]> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const result = await db.execute(
      `SELECT message FROM gateway_events
        WHERE category = 'system' AND server_name = 'audit-storage'
        ORDER BY occurred_at` as never,
    );
    if (result.rows.length > 0) {
      return result.rows.map((row) => String(row.message));
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return [];
}

describeIfDb("the tripwire reports through the table it monitors", () => {
  beforeAll(async () => {
    if (!TEST_DATABASE_URL) return;

    // All three of these are read at import time (the db modules read
    // DATABASE_URL, the tripwire parses its config once), so they have to be
    // set BEFORE the first dynamic import below.
    process.env.DATABASE_URL = TEST_DATABASE_URL;
    process.env.AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS = "1";
    // Low enough that the rows below cross it. The threshold is the knob under
    // test only in the sense that the crossing has to be reachable at all.
    process.env.AUDIT_STORAGE_WARN_MB = "1";

    ({ db } = await import("@/db/index"));

    // Past 1 MB of table, so the crossing is real growth rather than an
    // arithmetic fixture.
    await db.execute(
      `INSERT INTO gateway_events (category, message, server_name)
       SELECT 'system', repeat('x', 900) || g, 'itest-tripwire-fill'
       FROM generate_series(1, 3000) AS g` as never,
    );

    ({ checkAuditStorage } = await import("./tripwire"));
  });

  afterAll(async () => {
    if (!TEST_DATABASE_URL || !db) return;
    const { pool } = await import("@/db/index");
    const { gatewayEventsPool } = await import("@/db/gateway-events-db");
    await Promise.all([pool.end(), gatewayEventsPool.end()]);
  });

  it("writes a system event carrying the size that tripped it", async () => {
    await checkAuditStorage();

    const messages = await tripwireMessages();

    expect(messages).toHaveLength(1);
    expect(messages[0]).toContain("gateway_events is");
    expect(messages[0]).toContain("AUDIT_STORAGE_WARN_MB=1");
    // The operator's next question, answered in the row itself: lowering
    // retention will not reclaim this space until the window passes.
    expect(messages[0]).toContain("30-day immutability window");
  });

  it("does not write a second row while the condition persists", async () => {
    await checkAuditStorage();
    await checkAuditStorage();
    // Give any extra detached write the same chance to land as the first one,
    // so a row that DID get written cannot pass this by being slow.
    await new Promise((resolve) => setTimeout(resolve, 250));

    // The hysteresis is what keeps the monitor from filling the table it is
    // warning about. Without it a five-minute sweep would add 288 rows a day.
    expect(await tripwireMessages()).toHaveLength(1);
  });
});
