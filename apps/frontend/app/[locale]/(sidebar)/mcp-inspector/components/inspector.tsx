"use client";

import { RequestOptions } from "@modelcontextprotocol/sdk/shared/protocol.js";
import { ClientRequest } from "@modelcontextprotocol/sdk/types.js";
import {
  ActivitySquare,
  FileText,
  FolderTree,
  Info,
  type LucideIcon,
  MessageSquare,
  SearchCode,
  Wrench,
  Zap,
} from "lucide-react";
import { useState } from "react";
import { z } from "zod";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useTranslations } from "@/hooks/useTranslations";
import {
  type InspectorTabId,
  type InspectorTargetKind,
  visibleTabs,
} from "@/lib/inspector/inspector-target";
import type { InspectorServerInfo as ServerInfo } from "@/lib/inspector/server-info";

import { InspectorPing } from "./inspector/inspector-ping";
import { InspectorPrompts } from "./inspector/inspector-prompts";
import { InspectorResources } from "./inspector/inspector-resources";
import { InspectorRoots } from "./inspector/inspector-roots";
import { InspectorSampling } from "./inspector/inspector-sampling";
import { InspectorTools } from "./inspector/inspector-tools";
import { InspectorServerInfo } from "./inspector-server-info";

interface InspectorProps {
  mcpServerUuid: string;
  makeRequest: <T extends z.ZodType>(
    request: ClientRequest,
    schema: T,
    options?: RequestOptions & { suppressToast?: boolean },
  ) => Promise<z.output<T>>;
  serverCapabilities?: Record<string, unknown> | null;
  targetKind: InspectorTargetKind;
  serverInfo: ServerInfo | null;
}

// Tailwind only emits classes it can read as whole strings, so the column
// count is looked up here instead of being built from the number of tabs.
const TAB_GRID_CLASS: Record<number, string> = {
  3: "grid-cols-3",
  7: "grid-cols-7",
};

const TAB_TRIGGERS: Record<
  InspectorTabId,
  { icon: LucideIcon; labelKey: string }
> = {
  tools: { icon: Wrench, labelKey: "inspector:tools" },
  resources: { icon: FileText, labelKey: "inspector:resources" },
  prompts: { icon: MessageSquare, labelKey: "inspector:prompts" },
  ping: { icon: Zap, labelKey: "inspector:ping" },
  roots: { icon: FolderTree, labelKey: "inspector:roots" },
  sampling: { icon: ActivitySquare, labelKey: "inspector:sampling" },
  serverInfo: { icon: Info, labelKey: "inspector:inspectorServerInfo.tab" },
};

export function Inspector({
  mcpServerUuid,
  makeRequest,
  serverCapabilities,
  targetKind,
  serverInfo,
}: InspectorProps) {
  const { t } = useTranslations();
  const [selectedTab, setActiveTab] = useState<string>("tools");

  // The tabs depend on the target (a gateway target serves tools only). A
  // selection that is not offered any more falls back to Tools.
  const tabs = visibleTabs(targetKind);
  const activeTab = tabs.some((tab) => tab === selectedTab)
    ? selectedTab
    : "tools";

  // Check server capabilities to determine which tabs to show
  const hasTools = serverCapabilities?.tools !== undefined;
  const hasResources = serverCapabilities?.resources !== undefined;
  const hasPrompts = serverCapabilities?.prompts !== undefined;
  const hasRoots = serverCapabilities?.roots !== undefined;
  const hasSampling = serverCapabilities?.sampling !== undefined;

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <SearchCode className="h-5 w-5 text-muted-foreground" />
        <h4 className="text-sm font-medium">{t("inspector:title")}</h4>
        <span className="text-xs text-muted-foreground">
          {t("inspector:subtitle")}
        </span>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList
          className={`grid w-full ${TAB_GRID_CLASS[tabs.length] ?? "grid-cols-7"}`}
        >
          {tabs.map((tab) => {
            const { icon: Icon, labelKey } = TAB_TRIGGERS[tab];
            return (
              <TabsTrigger
                key={tab}
                value={tab}
                className="flex items-center gap-1"
              >
                <Icon className="h-4 w-4" />
                {t(labelKey)}
              </TabsTrigger>
            );
          })}
        </TabsList>

        <div className="mt-4">
          {/*
            forceMount keeps the Tools tab mounted (and hidden, through the
            data-state selector) while another tab is open. Radix unmounts an
            inactive tab's content otherwise, which would drop the tool list,
            the form and the results, and lose track of a call that is still
            running. A force-mounted panel is always rendered and Radix does
            not set `hidden` on it, so the class does the hiding.
          */}
          <TabsContent
            value="tools"
            forceMount
            className="data-[state=inactive]:hidden"
          >
            <InspectorTools makeRequest={makeRequest} enabled={hasTools} />
          </TabsContent>

          {tabs.includes("resources") && (
            <TabsContent value="resources">
              <InspectorResources
                makeRequest={makeRequest}
                enabled={hasResources}
              />
            </TabsContent>
          )}

          {tabs.includes("prompts") && (
            <TabsContent value="prompts">
              <InspectorPrompts
                makeRequest={makeRequest}
                enabled={hasPrompts}
              />
            </TabsContent>
          )}

          <TabsContent value="ping">
            <InspectorPing makeRequest={makeRequest} />
          </TabsContent>

          {tabs.includes("roots") && (
            <TabsContent value="roots">
              <InspectorRoots enabled={hasRoots} />
            </TabsContent>
          )}

          {tabs.includes("sampling") && (
            <TabsContent value="sampling">
              <InspectorSampling
                mcpServerUuid={mcpServerUuid}
                makeRequest={makeRequest}
                enabled={hasSampling}
              />
            </TabsContent>
          )}

          <TabsContent value="serverInfo">
            <InspectorServerInfo
              serverInfo={serverInfo}
              targetKind={targetKind}
              t={t}
            />
          </TabsContent>
        </div>
      </Tabs>
    </div>
  );
}
