import { LinkDocsMore } from "@/components/docs/LinkDocsMore";
import { detectorGlossary } from "@/lib/detectors";
import {
  docsDetectorHref,
  docsThresholdsHref,
} from "@/lib/docs-links";

type DetailsDetectorGlossaryProps = {
  summary?: string;
};

/** Phase 67 — “What is this?” detector glossary (static copy). Phase 77 — Docs links. */
export function DetailsDetectorGlossary({
  summary = "What is this? Detector glossary",
}: DetailsDetectorGlossaryProps) {
  const entries = detectorGlossary();

  return (
    <details className="fft-paper-panel p-4">
      <summary className="cursor-pointer text-sm font-medium">{summary}</summary>
      <div className="mt-3 flex flex-col gap-3 text-sm">
        <p className="text-base-content/70">
          Each badge is a detection family. Cutoffs (often 4.0 MAD robust z)
          are lab heuristics, not calibrated p-values.{" "}
          <LinkDocsMore href={docsThresholdsHref()}>
            Threshold policy
          </LinkDocsMore>
        </p>
        <dl className="grid gap-3 sm:grid-cols-2">
          {entries.map((entry) => (
            <div key={entry.id}>
              <dt className="font-medium">
                <span className="badge badge-outline badge-sm mr-2">
                  {entry.role}
                </span>
                <span className="fft-mono-meta">{entry.label}</span>
              </dt>
              <dd className="mt-1 text-base-content/80">
                {entry.meaning}{" "}
                <LinkDocsMore href={docsDetectorHref(entry.id)}>
                  Docs
                </LinkDocsMore>
              </dd>
            </div>
          ))}
        </dl>
      </div>
    </details>
  );
}
