"use client";

import { useEffect, useState } from "react";

export default function ThemeToggle() {
  const [dark, setDark] = useState(true);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setDark(
      document.documentElement.classList.contains("dark")
    );

    setMounted(true);
  }, []);

  function toggleTheme() {
    const nextTheme = !dark;

    setDark(nextTheme);

    document.documentElement.classList.toggle(
      "dark",
      nextTheme
    );

    document.documentElement.style.colorScheme =
      nextTheme ? "dark" : "light";

    localStorage.setItem(
      "sentinel-theme",
      nextTheme ? "dark" : "light"
    );
  }

  if (!mounted) {
    return (
      <div className="h-10 w-10 rounded-xl border border-zinc-200 bg-white dark:border-zinc-800 dark:bg-zinc-900" />
    );
  }

  return (
    <button
      type="button"
      onClick={toggleTheme}
      title={dark ? "Switch to light mode" : "Switch to dark mode"}
      aria-label={
        dark ? "Switch to light mode" : "Switch to dark mode"
      }
      className="flex h-10 w-10 items-center justify-center rounded-xl border border-zinc-200 bg-white text-zinc-700 shadow-sm transition hover:bg-zinc-100 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-300 dark:hover:bg-zinc-800"
    >
      {dark ? (
        <svg
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.8"
          className="h-5 w-5"
        >
          <circle cx="12" cy="12" r="4" />

          <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" />
        </svg>
      ) : (
        <svg
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.8"
          className="h-5 w-5"
        >
          <path d="M20.5 14.2A8.3 8.3 0 0 1 9.8 3.5a8.5 8.5 0 1 0 10.7 10.7Z" />
        </svg>
      )}
    </button>
  );
}