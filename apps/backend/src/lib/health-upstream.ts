import express from "express";

import { auth } from "../auth";
import { usersRepository } from "../db/repositories";
import { getBaseUrl } from "../routers/oauth/utils";
import logger from "../utils/logger";

/**
 * The two access decisions behind `GET /health/upstream`.
 *
 * They live here rather than inline in `index.ts` for one reason: `index.ts`
 * calls `app.listen()` at module load, so nothing in it can be imported by a
 * test. The endpoint now returns different data to different callers, and
 * "does a non-admin still get the detail half?" is exactly the question that
 * has to stay pinned by a test rather than by review memory.
 *
 * `index.ts` keeps the express wiring and the rollup arithmetic; this module
 * owns who-sees-what.
 */

/** Fields every caller gets, authenticated or not. */
export interface UpstreamLiveness {
  healthy: boolean;
  total_servers: number;
  errored_servers: number;
  unreachable_servers: number;
}

/**
 * Fields only an admin gets.
 *
 * `servers` enumerates every backend MCP by UUID and name — a map of the
 * estate's integrations. `pool` publishes live connection counts and the
 * configured caps, which is enough to size a resource-exhaustion attempt
 * against the gateway. Both were previously served to anyone who could reach
 * the URL.
 */
export interface UpstreamAdminDetail {
  pool: Record<string, unknown>;
  servers: unknown[];
}

/**
 * Assemble the response body. Pass `null` for `detail` to withhold the
 * admin-only half.
 *
 * Building the object additively (rather than deleting keys from a full one)
 * is deliberate: a field added to the detail half later cannot leak by
 * someone forgetting to add it to a redaction list.
 */
export function buildUpstreamHealthBody(
  liveness: UpstreamLiveness,
  detail: UpstreamAdminDetail | null,
): Record<string, unknown> {
  const body: Record<string, unknown> = {
    status: "ok",
    healthy: liveness.healthy,
    total_servers: liveness.total_servers,
    errored_servers: liveness.errored_servers,
    unreachable_servers: liveness.unreachable_servers,
  };

  if (detail) {
    body.pool = detail.pool;
    body.servers = detail.servers;
  }

  return body;
}

/**
 * Body for the 500 branch of the same endpoint.
 *
 * Constant by construction. The branch previously serialised
 * `error.message`, which on the failure this catch actually sees — a pg or
 * driver error — carries internal hostnames, ports and SQL fragments, and
 * served them to the same unauthenticated caller the success path was just
 * hardened against. The real error is logged at the call site instead, so
 * nothing is swallowed; only the wire form is constant.
 *
 * A fresh object per call rather than a shared frozen one: express serialises
 * it immediately, and a shared instance is an invitation for a later caller
 * to mutate the response of every other.
 */
export function buildUpstreamHealthErrorBody(): Record<string, unknown> {
  return {
    status: "error",
    healthy: false,
  };
}

/**
 * Resolve the caller's better-auth session and report whether they hold the
 * admin role.
 *
 * SOFT by construction: every failure mode — no cookie, an invalid or expired
 * session, an unknown user, a database hiccup — returns false rather than
 * throwing or rejecting the request. That shape exists because the caller is
 * an unauthenticated health endpoint: external monitors must keep getting
 * their 200 with the liveness fields, so this must never 401 and must never
 * throw. Because the failure direction is "not an admin", a broken session
 * check hides detail rather than exposing it.
 *
 * The role is read from the database (`findRoleById`) rather than from the
 * session payload, so the decision does not depend on how better-auth happens
 * to serialise `additionalFields`.
 */
export async function isAdminHealthRequest(
  req: express.Request,
): Promise<boolean> {
  if (!req.headers.cookie) return false;

  try {
    const headers = new Headers();
    headers.set("cookie", req.headers.cookie);

    const sessionResponse = await auth.handler(
      new Request(
        new URL("/api/auth/get-session", getBaseUrl(req)).toString(),
        {
          method: "GET",
          headers,
        },
      ),
    );

    if (!sessionResponse.ok) return false;

    const sessionData = (await sessionResponse.json()) as {
      user?: { id?: string };
    };
    const userId = sessionData?.user?.id;
    if (!userId) return false;

    if ((await usersRepository.findRoleById(userId)) !== "admin") return false;

    // `users.disabled` enforcement (migration 0027). What an admin answer
    // buys here is reconnaissance: the detail half of `/health/upstream` is
    // the estate map (every backend MCP by UUID and name, plus live pool
    // counts and caps), and `/health/sessions` and the endpoint/namespace
    // directory on `GET /` gate on this same function. A disabled admin
    // holding a live session cookie would otherwise keep reading all three —
    // precisely the survey an attacker runs first, and precisely what the
    // lockout exists to stop.
    //
    // Ordered after the role check so only an actual admin pays a second
    // query; the answer is identical either way. Disabled takes the SAME
    // closed path the rest of this function takes — return false, i.e.
    // liveness-only — rather than throwing, because the contract above is
    // that this never turns a monitor's 200 into a 401 or a 500.
    // `isDisabled` fails closed on its own (an id with no row reads as
    // disabled), and if the query itself throws, the catch below answers
    // non-admin.
    return !(await usersRepository.isDisabled(userId));
  } catch (error) {
    // Logged, not silently discarded: a session check that starts failing
    // would otherwise surface only as admins mysteriously losing the detail
    // half of this response, with nothing in the logs to explain it.
    logger.error("Session check failed for /health/upstream:", error);
    return false;
  }
}
