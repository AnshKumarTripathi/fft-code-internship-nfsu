"use client";

import { NavDocsToc } from "@/components/docs/NavDocsToc";

type ShellDocsProps = {
  activeSlug?: string;
  children: React.ReactNode;
};

export function ShellDocs({ activeSlug, children }: ShellDocsProps) {
  return (
    <div className="fft-page">
      <div className="flex flex-col gap-8 lg:flex-row lg:items-start">
        <aside className="w-full shrink-0 lg:sticky lg:top-4 lg:w-64 lg:self-start">
          <details className="fft-paper-panel lg:hidden">
            <summary className="cursor-pointer px-4 py-3 text-sm font-medium">
              Contents
            </summary>
            <div className="border-t border-base-300 px-3 py-3">
              <NavDocsToc activeSlug={activeSlug} />
            </div>
          </details>
          <div className="fft-paper-panel hidden p-3 lg:block">
            <p className="mb-2 px-2 text-xs font-semibold uppercase tracking-wide text-base-content/50">
              Contents
            </p>
            <NavDocsToc activeSlug={activeSlug} />
          </div>
        </aside>
        <div className="min-w-0 flex-1">{children}</div>
      </div>
    </div>
  );
}
