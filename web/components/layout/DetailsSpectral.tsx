"use client";

import { useState } from "react";

type DetailsSpectralProps = {
  summary?: string;
  children: React.ReactNode;
  onOpenChange?: (open: boolean) => void;
};

export function DetailsSpectral({
  summary = "Show spectral details",
  children,
  onOpenChange,
}: DetailsSpectralProps) {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <details
      className="fft-paper-panel bg-base-200 p-4"
      onToggle={(event) => {
        const open = (event.target as HTMLDetailsElement).open;
        setIsOpen(open);
        onOpenChange?.(open);
      }}
    >
      <summary className="cursor-pointer text-sm font-medium">
        {summary}
      </summary>
      {isOpen ? <div className="mt-4 flex flex-col gap-4">{children}</div> : null}
    </details>
  );
}
