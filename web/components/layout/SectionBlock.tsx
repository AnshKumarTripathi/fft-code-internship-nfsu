type SectionBlockProps = {
  title: string;
  description?: React.ReactNode;
  children: React.ReactNode;
  actions?: React.ReactNode;
};

export function SectionBlock({
  title,
  description,
  children,
  actions,
}: SectionBlockProps) {
  return (
    <section className="fft-section">
      <div className="flex flex-wrap items-start justify-between gap-2 border-b border-base-300 pb-2">
        <div>
          <h2 className="text-base font-semibold">{title}</h2>
          {description ? (
            <div className="mt-0.5 max-w-2xl text-sm text-base-content/70">
              {description}
            </div>
          ) : null}
        </div>
        {actions ? <div className="flex flex-wrap gap-2">{actions}</div> : null}
      </div>
      {children}
    </section>
  );
}
