import "./globals.css";

import type { Metadata } from "next";
import localFont from "next/font/local";
import { PublicEnvScript } from "next-runtime-env";
import { Toaster } from "sonner";

import { ThemeProvider } from "../components/providers/theme-provider";
import { TRPCProvider } from "../components/providers/trpc-provider";

const geistSans = localFont({
  src: "./fonts/GeistVF.woff",
  variable: "--font-geist-sans",
});
const geistMono = localFont({
  src: "./fonts/GeistMonoVF.woff",
  variable: "--font-geist-mono",
});

// Umbrella IT Group fork — see UMBRELLA_FORK.md for fork rationale.
// Branded for our private deployment; upstream metadata kept in
// upstream/main so a clean rebase reverts cleanly if we ever go
// non-private.
export const metadata: Metadata = {
  title: "Umbrella MCP Gateway",
  description:
    "Umbrella IT Group's MCP gateway — aggregates Autotask, IT Glue, CIPP, registry and more into curated namespaces for AI tooling.",
};

interface RootLayoutProps {
  children: React.ReactNode;
}

export default function RootLayout({ children }: RootLayoutProps) {
  return (
    <html suppressHydrationWarning>
      <head>
        <PublicEnvScript />
      </head>
      <body className={`${geistSans.variable} ${geistMono.variable}`}>
        <ThemeProvider>
          <TRPCProvider>
            {children}
            <Toaster richColors position="top-right" closeButton />
          </TRPCProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
