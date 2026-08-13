import { MetaMcpLogEntry } from "@repo/zod-types";
import { create } from "zustand";
import { subscribeWithSelector } from "zustand/middleware";

import { vanillaTrpcClient } from "../trpc";

interface LogsState {
  logs: MetaMcpLogEntry[];
  isLoading: boolean;
  isAutoRefreshing: boolean;
  totalCount: number;
  lastFetch: Date | null;

  // Actions
  fetchLogs: () => Promise<void>;
  clearLogs: () => Promise<void>;
  startAutoRefresh: () => void;
  stopAutoRefresh: () => void;
  setAutoRefresh: (enabled: boolean) => void;
}

let refreshInterval: NodeJS.Timeout | null = null;
const REFRESH_INTERVAL = 2000; // 2 seconds
const AUTO_REFRESH_STORAGE_KEY = "metamcp-auto-refresh-enabled";

// Helper functions for localStorage
const getStoredAutoRefreshState = (): boolean => {
  if (typeof window === "undefined") return true;
  const stored = localStorage.getItem(AUTO_REFRESH_STORAGE_KEY);
  return stored ? JSON.parse(stored) : true; // Default to true (enabled)
};

const setStoredAutoRefreshState = (enabled: boolean): void => {
  if (typeof window === "undefined") return;
  localStorage.setItem(AUTO_REFRESH_STORAGE_KEY, JSON.stringify(enabled));
};

// Errors that will not resolve by polling again. UNAUTHORIZED is the
// logged-out case; FORBIDDEN is the steady state for a member now that
// logs.get is adminProcedure. This store starts polling on import — not on
// visiting /live-logs — so without a stop condition a member's browser would
// re-issue a guaranteed-failing request every 2s from every page, for the
// whole session. The tRPC error code is read from the structured payload
// first, with a message match as fallback for transport-level shapes that
// carry no `data`.
const isTerminalAuthError = (error: unknown): boolean => {
  if (!error || typeof error !== "object") return false;

  const code = (error as { data?: { code?: string } }).data?.code;
  if (code === "UNAUTHORIZED" || code === "FORBIDDEN") return true;

  if ("message" in error) {
    const message = String((error as { message?: unknown }).message);
    return (
      message.includes("UNAUTHORIZED") ||
      message.includes("FORBIDDEN") ||
      message.includes("You must be logged in") ||
      message.includes("administrator role")
    );
  }

  return false;
};

export const useLogsStore = create<LogsState>()(
  subscribeWithSelector((set, get) => ({
    logs: [],
    isLoading: false,
    isAutoRefreshing: getStoredAutoRefreshState(), // Load from localStorage
    totalCount: 0,
    lastFetch: null,

    fetchLogs: async () => {
      try {
        set({ isLoading: true });

        const response = await vanillaTrpcClient.frontend.logs.get.query({
          limit: 1000,
        });

        if (response.success) {
          set({
            logs:
              response.data?.map((log) => ({
                ...log,
                timestamp: new Date(log.timestamp),
              })) || [],
            totalCount: response.totalCount || 0,
            lastFetch: new Date(),
            isLoading: false,
          });
        }
      } catch (error) {
        console.error("Failed to fetch logs:", error);
        set({ isLoading: false });

        // Stop auto-refresh if the user is not authenticated, or not allowed
        if (isTerminalAuthError(error)) {
          const currentState = get();
          if (currentState.isAutoRefreshing) {
            currentState.stopAutoRefresh();
            console.log(
              "Auto-refresh stopped due to authentication/authorization error",
            );
          }
        }
      }
    },

    clearLogs: async () => {
      try {
        await vanillaTrpcClient.frontend.logs.clear.mutate();
        set({ logs: [], totalCount: 0 });
      } catch (error) {
        console.error("Failed to clear logs:", error);

        // Check if it's an authentication error
        if (error && typeof error === "object" && "message" in error) {
          const errorMessage = String(error.message);
          if (
            errorMessage.includes("UNAUTHORIZED") ||
            errorMessage.includes("You must be logged in")
          ) {
            // Stop auto-refresh if user is not authenticated
            const currentState = get();
            if (currentState.isAutoRefreshing) {
              currentState.stopAutoRefresh();
              console.log(
                "Auto-refresh stopped due to authentication error in clearLogs",
              );
            }
          }
        }
      }
    },

    startAutoRefresh: () => {
      const state = get();
      if (refreshInterval) return; // Already running

      // Fetch immediately
      state.fetchLogs();

      // Set up interval
      refreshInterval = setInterval(() => {
        const currentState = get();
        if (currentState.isAutoRefreshing) {
          currentState.fetchLogs();
        }
      }, REFRESH_INTERVAL);

      set({ isAutoRefreshing: true });
      setStoredAutoRefreshState(true); // Persist to localStorage
    },

    stopAutoRefresh: () => {
      if (refreshInterval) {
        clearInterval(refreshInterval);
        refreshInterval = null;
      }
      set({ isAutoRefreshing: false });
      setStoredAutoRefreshState(false); // Persist to localStorage
    },

    setAutoRefresh: (enabled: boolean) => {
      if (enabled) {
        get().startAutoRefresh();
      } else {
        get().stopAutoRefresh();
      }
    },
  })),
);

// Initialize auto-refresh based on stored preference
if (typeof window !== "undefined") {
  // Only start in browser environment and if user previously enabled it
  setTimeout(() => {
    const shouldAutoRefresh = getStoredAutoRefreshState();
    if (shouldAutoRefresh) {
      useLogsStore.getState().startAutoRefresh();
    }
    // Always fetch logs once when the page loads
    useLogsStore.getState().fetchLogs();
  }, 100);
}

// Cleanup on page unload
if (typeof window !== "undefined") {
  window.addEventListener("beforeunload", () => {
    if (refreshInterval) {
      clearInterval(refreshInterval);
    }
  });
}
