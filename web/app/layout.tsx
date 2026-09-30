import type { Metadata } from "next";
import { IBM_Plex_Mono, IBM_Plex_Sans } from "next/font/google";
import { ShellApp } from "@/components/layout/ShellApp";
import { THEME_BOOT_SCRIPT } from "@/lib/theme";
import "./globals.css";

const ibmPlexSans = IBM_Plex_Sans({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-ibm-plex-sans",
  display: "swap",
});

const ibmPlexMono = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["400", "500"],
  variable: "--font-ibm-plex-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "Log Anomaly",
  description:
    "Read-only incident investigation UI. Local trusted network — no login.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      data-theme="fft"
      className={`h-full ${ibmPlexSans.variable} ${ibmPlexMono.variable}`}
      suppressHydrationWarning
    >
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_BOOT_SCRIPT }} />
      </head>
      <body
        className={`${ibmPlexSans.className} flex min-h-full flex-col bg-base-100 font-sans text-base-content antialiased`}
        suppressHydrationWarning
      >
        <ShellApp>{children}</ShellApp>
      </body>
    </html>
  );
}
