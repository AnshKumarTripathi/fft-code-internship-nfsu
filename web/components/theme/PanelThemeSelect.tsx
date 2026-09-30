"use client";

import { useTheme } from "@/components/theme/ProviderTheme";
import { THEME_OPTIONS, type ThemeId } from "@/lib/theme";

export function PanelThemeSelect() {
  const { theme, setTheme } = useTheme();

  return (
    <fieldset className="fft-paper-panel flex flex-col gap-3 p-4">
      <legend className="px-1 text-sm font-semibold">Appearance</legend>
      <p className="text-sm text-base-content/70">
        Choose a color theme for the lab console. Saved in this browser.
      </p>
      <div className="flex flex-col gap-2" role="radiogroup" aria-label="Theme">
        {THEME_OPTIONS.map((option) => {
          const checked = theme === option.id;
          const inputId = `theme-${option.id}`;
          return (
            <label
              key={option.id}
              htmlFor={inputId}
              className={`flex cursor-pointer items-start gap-3 rounded-box border px-3 py-3 transition-colors ${
                checked
                  ? "border-primary bg-primary/10"
                  : "border-base-300 hover:bg-base-200/60"
              }`}
            >
              <input
                id={inputId}
                type="radio"
                name="theme"
                className="radio radio-primary mt-0.5"
                checked={checked}
                value={option.id}
                onChange={() => setTheme(option.id as ThemeId)}
              />
              <span className="min-w-0 flex-1">
                <span className="block text-sm font-medium">{option.label}</span>
                <span className="mt-0.5 block text-xs text-base-content/60">
                  {option.description}
                </span>
              </span>
            </label>
          );
        })}
      </div>
    </fieldset>
  );
}
