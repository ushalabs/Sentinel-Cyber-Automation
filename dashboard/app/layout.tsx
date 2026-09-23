import type { Metadata } from "next";
import type { ReactNode } from "react";
import Script from "next/script";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Sentinel | Security Operations",
  description:
    "AI-powered network threat detection, analysis and incident response",
};

const themeScript = `
(function () {
  try {
    const savedTheme = localStorage.getItem("sentinel-theme");
    const useDark = savedTheme ? savedTheme === "dark" : true;

    document.documentElement.classList.toggle("dark", useDark);
    document.documentElement.style.colorScheme =
      useDark ? "dark" : "light";
  } catch (_) {}
})();
`;

export default function RootLayout({
  children,
}: {
  children: ReactNode;
}) {
  return (
    <html
      lang="en"
      suppressHydrationWarning
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full bg-zinc-50 text-zinc-950 transition-colors duration-200 dark:bg-zinc-950 dark:text-zinc-50">
        <Script
          id="sentinel-theme-init"
          strategy="beforeInteractive"
          dangerouslySetInnerHTML={{
            __html: themeScript,
          }}
        />

        {children}
      </body>
    </html>
  );
}
