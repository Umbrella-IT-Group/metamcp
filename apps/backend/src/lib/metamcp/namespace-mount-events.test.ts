import { describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import logger from "@/utils/logger";

import {
  namespaceMountListenerCount,
  notifyNamespaceMountChange,
  onNamespaceMountChange,
} from "./namespace-mount-events";

describe("namespace mount change signal", () => {
  it("reaches every listener of the namespace and no other namespace", () => {
    const here = vi.fn();
    const alsoHere = vi.fn();
    const elsewhere = vi.fn();
    const stops = [
      onNamespaceMountChange("ns-a", here),
      onNamespaceMountChange("ns-a", alsoHere),
      onNamespaceMountChange("ns-b", elsewhere),
    ];

    expect(notifyNamespaceMountChange("ns-a", "server-1")).toBe(2);
    expect(here).toHaveBeenCalledWith("server-1");
    expect(alsoHere).toHaveBeenCalledWith("server-1");
    expect(elsewhere).not.toHaveBeenCalled();
    for (const stop of stops) stop();
  });

  it("a removed listener is not called and an empty namespace is dropped", () => {
    const listener = vi.fn();
    const stop = onNamespaceMountChange("ns-c", listener);
    expect(namespaceMountListenerCount("ns-c")).toBe(1);
    stop();
    stop();
    expect(namespaceMountListenerCount("ns-c")).toBe(0);
    expect(notifyNamespaceMountChange("ns-c", "server-1")).toBe(0);
    expect(listener).not.toHaveBeenCalled();
  });

  it("a listener that throws is logged and does not stop the others", () => {
    const failing = vi.fn(() => {
      throw new Error("listener failed");
    });
    const after = vi.fn();
    const stops = [
      onNamespaceMountChange("ns-d", failing),
      onNamespaceMountChange("ns-d", after),
    ];
    expect(notifyNamespaceMountChange("ns-d", "server-1")).toBe(1);
    expect(after).toHaveBeenCalledWith("server-1");
    expect(logger.error).toHaveBeenCalledTimes(1);
    for (const stop of stops) stop();
  });

  it("a listener that unregisters itself while being called does not skip another", () => {
    const calls: string[] = [];
    const stopFirst = onNamespaceMountChange("ns-e", () => {
      calls.push("first");
      stopFirst();
    });
    const stopSecond = onNamespaceMountChange("ns-e", () => {
      calls.push("second");
    });
    expect(notifyNamespaceMountChange("ns-e", "server-1")).toBe(2);
    expect(calls).toEqual(["first", "second"]);
    stopSecond();
    expect(namespaceMountListenerCount("ns-e")).toBe(0);
  });
});
