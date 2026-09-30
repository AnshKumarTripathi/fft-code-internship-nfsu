export const THEME_STORAGE_KEY = "fft-theme";

export const THEME_IDS = ["fft", "solarized-dark"] as const;

export type ThemeId = (typeof THEME_IDS)[number];

export const DEFAULT_THEME: ThemeId = "fft";

export type ThemeOption = {
  id: ThemeId;
  label: string;
  description: string;
};

export const THEME_OPTIONS: ThemeOption[] = [
  {
    id: "fft",
    label: "Lab paper",
    description: "Light cool paper with blue chrome. Default lab console look.",
  },
  {
    id: "solarized-dark",
    label: "Solarized Dark",
    description:
      "Ethan Schoonover’s Solarized Dark — low-contrast dark bases with solarized accents.",
  },
];

export function isThemeId(value: string | null | undefined): value is ThemeId {
  return THEME_IDS.includes(value as ThemeId);
}

export function readStoredTheme(): ThemeId {
  if (typeof window === "undefined") {
    return DEFAULT_THEME;
  }
  try {
    const raw = window.localStorage.getItem(THEME_STORAGE_KEY);
    return isThemeId(raw) ? raw : DEFAULT_THEME;
  } catch {
    return DEFAULT_THEME;
  }
}

export function writeStoredTheme(theme: ThemeId): void {
  if (typeof window === "undefined") {
    return;
  }
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    /* ignore quota / private mode */
  }
}

export function applyThemeToDocument(theme: ThemeId): void {
  if (typeof document === "undefined") {
    return;
  }
  document.documentElement.setAttribute("data-theme", theme);
}

/** Inline boot script — apply stored theme before paint to avoid FOUC. */
export const THEME_BOOT_SCRIPT = `(function(){try{var k=${JSON.stringify(THEME_STORAGE_KEY)};var t=localStorage.getItem(k);if(t===${JSON.stringify("fft")}||t===${JSON.stringify("solarized-dark")}){document.documentElement.setAttribute("data-theme",t);}}catch(e){}})();`;
