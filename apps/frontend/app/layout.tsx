import "./globals.css";

import type { Metadata } from "next";
import localFont from "next/font/local";
import { PublicEnvScript } from "next-runtime-env";
import { Toaster } from "sonner";

import { ThemeProvider } from "../components/providers/theme-provider";
import { TRPCProvider } from "../components/providers/trpc-provider";
import { getBranding } from "../lib/branding";

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
//
// This is `generateMetadata`, not a static `metadata` object, so the title
// resolves per request instead of being frozen into the build output. That is
// what makes a rebrand a container restart rather than an image rebuild. Every
// route in this app already renders dynamically (the root layout's
// <PublicEnvScript /> opts out of caching), so there is no static-generation
// cost to pay for it. Defaults are the current Umbrella strings — see
// lib/branding.ts.
export function generateMetadata(): Metadata {
  const { productName, description } = getBranding();
  return {
    title: productName,
    description,
  };
}

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
