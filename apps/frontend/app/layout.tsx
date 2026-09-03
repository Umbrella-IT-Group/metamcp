import "./globals.css";

import type { Metadata } from "next";
import localFont from "next/font/local";
import { headers } from "next/headers";
import { PublicEnvScript } from "next-runtime-env";
import { Toaster } from "sonner";

import { ThemeProvider } from "../components/providers/theme-provider";
import { TRPCProvider } from "../components/providers/trpc-provider";
import { getBranding } from "../lib/branding";
import { NONCE_HEADER } from "../lib/security-headers";

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

export default async function RootLayout({ children }: RootLayoutProps) {
  // The CSP nonce minted per request in middleware.ts. Next nonces the scripts
  // it renders itself once it sees the nonce in the request's CSP header; these
  // two inline scripts are the ones it does not own: the runtime-env
  // bootstrap that publishes NEXT_PUBLIC_* to the browser, and the theme
  // anti-flash script, so the nonce is passed to them by hand. Without it both
  // are inline scripts with no nonce and `script-src` blocks them. See
  // ../lib/security-headers.
  const nonce = (await headers()).get(NONCE_HEADER) ?? undefined;
  return (
    <html suppressHydrationWarning>
      <head>
        <PublicEnvScript nonce={nonce} />
      </head>
      <body className={`${geistSans.variable} ${geistMono.variable}`}>
        <ThemeProvider nonce={nonce}>
          <TRPCProvider>
            {children}
            <Toaster richColors position="top-right" closeButton />
          </TRPCProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
