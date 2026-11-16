import type { Metadata } from "next";
// Self-hosted IBM Plex (OFL) from Fontsource: the build fetches nothing from
// Google Fonts, which failed on Vercel's builders with next/font/google.
import "@fontsource/ibm-plex-sans/latin-400.css";
import "@fontsource/ibm-plex-sans/latin-500.css";
import "@fontsource/ibm-plex-sans/latin-600.css";
import "@fontsource/ibm-plex-mono/latin-400.css";
import "@fontsource/ibm-plex-mono/latin-500.css";
import "./globals.css";

export const metadata: Metadata = {
  title: "Tripline",
  description:
    "What a coding agent actually did inside a recorded, policy-enforced sandbox: every program it ran, every host it reached and every action that was blocked.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
