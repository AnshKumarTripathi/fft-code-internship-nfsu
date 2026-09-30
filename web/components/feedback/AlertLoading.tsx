type AlertLoadingProps = {
  label?: string;
};

export function AlertLoading({
  label = "Loading warehouse data…",
}: AlertLoadingProps) {
  return (
    <div role="status" className="alert" aria-live="polite">
      <span className="loading loading-spinner loading-sm" aria-hidden="true" />
      <span>{label}</span>
    </div>
  );
}
