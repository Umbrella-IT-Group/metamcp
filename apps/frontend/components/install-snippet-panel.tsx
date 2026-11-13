import { Copy } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type {
  InstallAuth,
  InstallBlock,
  InstallBlockKind,
  InstallNote,
  InstallNoteKey,
  InstallOption,
  InstallSnippets,
} from "@/lib/install-snippets";

type Translate = (
  key: string,
  params?: Record<string, string | number>,
) => string;

// Every string is a literal here, not built from the builder's key, so a
// missing locale entry is found by reading this file (the i18n test does) and
// a new note key fails to compile until it has text.
const NOTE_TEXT = {
  apiKeyNote: "inspector:installClient.apiKeyNote",
  scopedKeyNote: "inspector:installClient.scopedKeyNote",
  envVarNote: "inspector:installClient.envVarNote",
  headerNote: "inspector:installClient.headerNote",
  oauthNote: "inspector:installClient.oauthNote",
  oauthLoopbackNote: "inspector:installClient.oauthLoopbackNote",
  claudeCodeMcpPanelNote: "inspector:installClient.claudeCodeMcpPanelNote",
  vscodeFormatNote: "inspector:installClient.vscodeFormatNote",
  noAuthNote: "inspector:installClient.noAuthNote",
  claudeStep1: "inspector:installClient.claudeStep1",
  claudeStep2: "inspector:installClient.claudeStep2",
  claudeStep3: "inspector:installClient.claudeStep3",
  claudeStep4: "inspector:installClient.claudeStep4",
  claudeTeamNote: "inspector:installClient.claudeTeamNote",
} as const satisfies Record<InstallNoteKey, string>;

const BLOCK_HEADING = {
  command: "inspector:installClient.blockCommand",
  config: "inspector:installClient.blockConfig",
  login: "inspector:installClient.blockLogin",
} as const satisfies Record<InstallBlockKind, string>;

const OPTION_HEADING = {
  apiKey: "inspector:installClient.optionApiKey",
  oauth: "inspector:installClient.optionOauth",
  none: null,
} as const satisfies Record<InstallAuth, string | null>;

function noteText(note: InstallNote, t: Translate): string {
  return t(NOTE_TEXT[note.key], note.params);
}

function BlockView({
  block,
  t,
  onCopy,
}: {
  block: InstallBlock;
  t: Translate;
  onCopy: (text: string) => void;
}) {
  return (
    <div className="space-y-1 min-w-0">
      <div className="flex items-center justify-between gap-2">
        <span className="text-sm font-medium">
          {t(BLOCK_HEADING[block.kind])}
        </span>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => onCopy(block.text)}
        >
          <Copy className="h-3.5 w-3.5" />
          {t("inspector:installClient.copy")}
        </Button>
      </div>
      {block.destinations.map((d) => (
        <p key={d.scope} className="text-xs text-muted-foreground">
          {t(
            d.scope === "project"
              ? "inspector:installClient.destProject"
              : "inspector:installClient.destUser",
            { path: d.path },
          )}
        </p>
      ))}
      {/* Plain text in a <pre>: what is copied is exactly what is shown, and
          nothing here can be read as markup. */}
      <pre className="rounded-md border bg-muted/40 p-3 text-xs whitespace-pre-wrap break-all">
        <code>{block.text}</code>
      </pre>
    </div>
  );
}

function OptionView({
  option,
  showHeading,
  t,
  onCopy,
}: {
  option: InstallOption;
  showHeading: boolean;
  t: Translate;
  onCopy: (text: string) => void;
}) {
  const headingKey = OPTION_HEADING[option.auth];
  return (
    <section className="space-y-3 min-w-0">
      {showHeading && headingKey ? (
        <h4 className="text-sm font-semibold">{t(headingKey)}</h4>
      ) : null}
      {option.steps.length > 0 ? (
        <ol className="list-decimal space-y-1 pl-5 text-sm">
          {option.steps.map((step) => (
            <li key={step.key}>{noteText(step, t)}</li>
          ))}
        </ol>
      ) : null}
      {option.blocks.map((block) => (
        <BlockView
          key={`${block.kind}:${block.language}`}
          block={block}
          t={t}
          onCopy={onCopy}
        />
      ))}
      {option.notes.length > 0 ? (
        <ul className="space-y-1 text-xs text-muted-foreground">
          {option.notes.map((note) => (
            <li key={note.key}>{noteText(note, t)}</li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}

/**
 * The tabs of snippets for one endpoint. Presentational: it takes the builder's
 * result, the translator and the copy action, so a test can render it with no
 * dialog, router or clipboard around it.
 */
export function InstallSnippetPanel({
  snippets,
  t,
  onCopy,
}: {
  snippets: InstallSnippets;
  t: Translate;
  onCopy: (text: string) => void;
}) {
  const tabs: { id: string; label: string; options: InstallOption[] }[] = [
    {
      id: "claudeCode",
      label: t("inspector:installClient.tabClaudeCode"),
      options: snippets.clients.claudeCode,
    },
    {
      id: "codex",
      label: t("inspector:installClient.tabCodex"),
      options: snippets.clients.codex,
    },
    {
      id: "cursor",
      label: t("inspector:installClient.tabCursor"),
      options: snippets.clients.cursor,
    },
    {
      id: "vscode",
      label: t("inspector:installClient.tabVsCode"),
      options: snippets.clients.vscode,
    },
  ];
  if (snippets.claudeWeb) {
    tabs.push({
      id: "claude",
      label: t("inspector:installClient.tabClaude"),
      options: [snippets.claudeWeb],
    });
  }

  return (
    <div className="space-y-4 min-w-0">
      <div className="space-y-1 min-w-0">
        <div className="flex items-center justify-between gap-2">
          <span className="text-sm font-medium">
            {t("inspector:installClient.urlLabel")}
          </span>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => onCopy(snippets.mcpUrl)}
          >
            <Copy className="h-3.5 w-3.5" />
            {t("inspector:installClient.copy")}
          </Button>
        </div>
        <pre className="rounded-md border bg-muted/40 p-3 text-xs whitespace-pre-wrap break-all">
          <code>{snippets.mcpUrl}</code>
        </pre>
      </div>
      <Tabs defaultValue="claudeCode">
        <TabsList className="h-auto flex-wrap justify-start">
          {tabs.map((tab) => (
            <TabsTrigger key={tab.id} value={tab.id}>
              {tab.label}
            </TabsTrigger>
          ))}
        </TabsList>
        {tabs.map((tab) => (
          <TabsContent key={tab.id} value={tab.id} className="space-y-5 pt-2">
            {tab.options.map((option) => (
              <OptionView
                key={option.auth}
                option={option}
                showHeading={tab.options.length > 1}
                t={t}
                onCopy={onCopy}
              />
            ))}
          </TabsContent>
        ))}
      </Tabs>
    </div>
  );
}
