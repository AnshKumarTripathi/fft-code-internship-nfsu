type BadgeFlagBandProps = {
  band?: string | null;
  flagged?: boolean;
};

export function BadgeFlagBand({ band, flagged }: BadgeFlagBandProps) {
  if (flagged || band === "flagged") {
    return <span className="badge badge-error">flagged</span>;
  }
  if (band === "near_miss") {
    return <span className="badge badge-warning">near miss</span>;
  }
  if (band === "below") {
    return <span className="badge badge-ghost">below</span>;
  }
  return <span className="badge badge-ghost">unknown</span>;
}
