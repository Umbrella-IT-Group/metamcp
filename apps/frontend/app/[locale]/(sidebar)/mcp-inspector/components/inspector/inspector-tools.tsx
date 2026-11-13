"use client";

import { RequestOptions } from "@modelcontextprotocol/sdk/shared/protocol.js";
import {
  ClientRequest,
  CompatibilityCallToolResultSchema,
  ListToolsResultSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import {
  AlertTriangle,
  Clock,
  Loader2,
  OctagonX,
  Play,
  Wrench,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { toast } from "sonner";
import { z } from "zod";

import { Button } from "@/components/ui/button";
import { useTranslations } from "@/hooks/useTranslations";
import { startToolCall, type ToolCallRun } from "@/lib/inspector/tool-call-run";
import {
  buildArguments,
  describeFields,
  type FormState,
  initialFormState,
} from "@/lib/inspector/tool-form";
import {
  classifyCallFailure,
  classifyCallResult,
  type ToolExecutionRecord,
} from "@/lib/inspector/tool-result";

import { ToolArgumentForm } from "./tools/tool-argument-form";
import { ToolList } from "./tools/tool-list";
import { ToolResultView } from "./tools/tool-result-view";

interface InspectorToolsProps {
  makeRequest: <T extends z.ZodType>(
    request: ClientRequest,
    schema: T,
    options?: RequestOptions & { suppressToast?: boolean },
  ) => Promise<z.output<T>>;
  enabled?: boolean;
}

// Memory only: older runs fall off the list. Nothing is stored anywhere.
const MAX_EXECUTIONS = 50;

const firstLine = (text: string) => text.split("\n", 1)[0] ?? text;

export function InspectorTools({
  makeRequest,
  enabled = true,
}: InspectorToolsProps) {
  const { t } = useTranslations();
  const [tools, setTools] = useState<Tool[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedTool, setSelectedTool] = useState<Tool | null>(null);
  const [formState, setFormState] = useState<FormState>(new Map());
  const [executions, setExecutions] = useState<ToolExecutionRecord[]>([]);
  const [executing, setExecuting] = useState(false);
  const [nextCursor, setNextCursor] = useState<string | undefined>();
  const runRef = useRef<ToolCallRun<unknown> | null>(null);
  const nextExecutionId = useRef(1);

  const specs = useMemo(
    () => (selectedTool ? describeFields(selectedTool) : []),
    [selectedTool],
  );
  const build = useMemo(
    () => buildArguments(specs, formState),
    [specs, formState],
  );

  // This component stays mounted while the Tools tab is hidden (see
  // inspector.tsx), so a running call survives switching tabs. When it does
  // unmount (the connection was closed, the target changed, the page was left)
  // the call is only detached from the UI. It is never aborted here: aborting
  // sends notifications/cancelled, and navigating away must not cancel a write
  // that is under way. Only the Stop waiting button cancels.
  useEffect(() => {
    return () => {
      runRef.current?.detach();
    };
  }, []);

  const selectTool = (tool: Tool | null) => {
    setSelectedTool(tool);
    setFormState(tool ? initialFormState(describeFields(tool)) : new Map());
  };

  // Fetch available tools with proper error handling pattern from official inspector
  const fetchTools = async (cursor?: string) => {
    if (!enabled) {
      toast.warning(t("inspector:toolsComponent.toolsNotSupportedWarning"));
      return;
    }

    setLoading(true);
    try {
      const response = await makeRequest(
        {
          method: "tools/list" as const,
          params: cursor ? { cursor } : {},
        },
        ListToolsResultSchema,
        { suppressToast: true },
      );

      if (cursor) {
        // Append to existing tools if we're fetching more
        setTools((prev) => [...prev, ...(response.tools || [])]);
      } else {
        // Replace tools if this is the first fetch
        setTools(response.tools || []);
      }

      setNextCursor(response.nextCursor);

      if (response.tools && response.tools.length > 0) {
        toast.success(
          t("inspector:toolsComponent.foundTools", {
            count: response.tools.length,
          }),
        );
        // Auto-select first tool if none selected
        if (!selectedTool && response.tools.length > 0) {
          selectTool(response.tools[0] as Tool);
        }
      } else {
        toast.info(t("inspector:toolsComponent.noToolsFound"));
      }
    } catch (error) {
      console.error("Error listing tools:", error);
      toast.error(t("inspector:toolsComponent.listTools"), {
        description: error instanceof Error ? error.message : String(error),
      });
      setTools([]);
    } finally {
      setLoading(false);
    }
  };

  const clearTools = () => {
    setTools([]);
    selectTool(null);
    setNextCursor(undefined);
    setExecutions([]);
  };

  const updateExecution = (id: number, patch: Partial<ToolExecutionRecord>) => {
    setExecutions((prev) =>
      prev.map((entry) => (entry.id === id ? { ...entry, ...patch } : entry)),
    );
  };

  // Call the selected tool with exactly the arguments the form builds.
  const executeTool = async () => {
    if (!selectedTool || executing || build.errors.length > 0) return;

    const toolName = selectedTool.name;
    const args = build.args;
    const id = nextExecutionId.current++;
    const startedAt = Date.now();
    const startedPerf = performance.now();

    setExecuting(true);
    setExecutions((prev) =>
      [
        { id, toolName, args, startedAt, status: "running" as const },
        ...prev,
      ].slice(0, MAX_EXECUTIONS),
    );

    const run = startToolCall((signal) =>
      makeRequest(
        {
          method: "tools/call" as const,
          params: { name: toolName, arguments: args },
        },
        CompatibilityCallToolResultSchema,
        { suppressToast: true, signal },
      ),
    );
    runRef.current = run;

    try {
      const response = await run.result;
      if (run.detached) return;

      const durationMs = Math.round(performance.now() - startedPerf);
      const classified = classifyCallResult(response);
      updateExecution(id, {
        status: classified.status,
        result: response,
        durationMs,
      });

      if (classified.status === "tool_error") {
        toast.error(
          t("inspector:inspectorResult.toolErrorToast", { toolName }),
          {
            description: firstLine(classified.errorText ?? ""),
          },
        );
      } else {
        toast.success(
          t("inspector:toolsComponent.toolExecutedSuccess", { toolName }),
          {
            description: t(
              "inspector:toolsComponent.toolExecutedSuccessDescription",
              { duration: durationMs },
            ),
          },
        );
      }
    } catch (error) {
      if (run.detached) return;

      const durationMs = Math.round(performance.now() - startedPerf);
      const failure = classifyCallFailure(error, {
        stoppedByUser: run.stoppedByUser,
      });
      updateExecution(id, { status: failure.status, failure, durationMs });

      if (failure.status === "stopped") {
        toast.info(t("inspector:inspectorResult.stoppedToast", { toolName }));
      } else {
        toast.error(
          t("inspector:toolsComponent.toolExecutionFailed", { toolName }),
          { description: failure.message },
        );
      }
    } finally {
      if (runRef.current === run) runRef.current = null;
      if (!run.detached) setExecuting(false);
    }
  };

  // Check if tools capability is disabled
  if (!enabled) {
    return (
      <div className="rounded-lg border border-dashed p-8 text-center">
        <AlertTriangle className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
        <h4 className="text-sm font-medium">
          {t("inspector:toolsComponent.toolsNotSupported")}
        </h4>
        <p className="text-sm text-muted-foreground mt-1">
          {t("inspector:toolsComponent.toolsNotSupportedDesc")}
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Wrench className="h-5 w-5 text-blue-500" />
          <span className="text-sm font-medium">
            {t("inspector:toolsComponent.title")}
          </span>
          <span className="text-xs text-muted-foreground">
            {t("inspector:toolsComponent.subtitle")}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={clearTools}
            disabled={loading || tools.length === 0}
          >
            {t("inspector:toolsComponent.clear")}
          </Button>
          <Button onClick={() => fetchTools()} disabled={loading} size="sm">
            {loading
              ? t("inspector:toolsComponent.loading")
              : t("inspector:toolsComponent.listTools")}
          </Button>
          {nextCursor && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => fetchTools(nextCursor)}
              disabled={loading}
            >
              {t("inspector:toolsComponent.loadMore")}
            </Button>
          )}
        </div>
      </div>

      {/* Main Content - Two Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left Column - Tools List */}
        <div className="space-y-4">
          <h5 className="text-sm font-medium">
            {t("inspector:toolsComponent.toolsCount", { count: tools.length })}
          </h5>

          <ToolList
            tools={tools}
            selectedTool={selectedTool}
            onSelect={selectTool}
            loading={loading}
            t={t}
          />

          {/* Tool Details and Arguments */}
          {selectedTool && (
            <div className="space-y-4">
              <div>
                <h6 className="text-sm font-medium mb-2">
                  {t("inspector:toolsComponent.toolDetails")}
                </h6>
                <div className="rounded-lg border p-3">
                  <div className="font-mono text-sm mb-1">
                    {selectedTool.name}
                  </div>
                  {selectedTool.description && (
                    <p className="text-xs text-muted-foreground">
                      {selectedTool.description}
                    </p>
                  )}
                </div>
              </div>

              <div>
                <h6 className="text-sm font-medium mb-2">
                  {t("inspector:toolsComponent.arguments")}
                </h6>
                <ToolArgumentForm
                  // A fresh form (and a closed "fill from JSON" box) per tool.
                  key={selectedTool.name}
                  specs={specs}
                  state={formState}
                  build={build}
                  onStateChange={setFormState}
                  t={t}
                />
              </div>

              {/* Execute Button */}
              <div className="space-y-2">
                <div className="flex gap-2">
                  <Button
                    onClick={executeTool}
                    disabled={executing || build.errors.length > 0}
                    className="flex flex-1 items-center gap-2"
                  >
                    {executing ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Play className="h-4 w-4" />
                    )}
                    {executing
                      ? t("inspector:toolsComponent.calling")
                      : t("inspector:toolsComponent.callTool")}
                  </Button>
                  {executing && (
                    <Button
                      variant="outline"
                      onClick={() => runRef.current?.stop()}
                      className="flex items-center gap-2"
                    >
                      <OctagonX className="h-4 w-4" />
                      {t("inspector:inspectorResult.stopWaiting")}
                    </Button>
                  )}
                </div>
                {executing && (
                  <p className="text-xs text-muted-foreground">
                    {t("inspector:inspectorResult.stopWaitingHelp")}
                  </p>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Right Column - Execution and History */}
        <div className="space-y-4">
          <h5 className="text-sm font-medium">
            {t("inspector:toolsComponent.executionHistoryCount", {
              count: executions.length,
            })}
          </h5>

          {executions.length > 0 ? (
            <div className="space-y-3 max-h-[600px] overflow-y-auto">
              {executions.map((execution) => (
                <ToolResultView
                  key={execution.id}
                  execution={execution}
                  t={t}
                />
              ))}
            </div>
          ) : (
            <div className="rounded-lg border border-dashed p-6 text-center">
              <Clock className="h-6 w-6 text-muted-foreground mx-auto mb-2" />
              <p className="text-sm text-muted-foreground">
                {t("inspector:toolsComponent.noExecutions")}
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
