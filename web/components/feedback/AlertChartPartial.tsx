type AlertChartPartialProps = {
  source: string;
};

export function AlertChartPartial({ source }: AlertChartPartialProps) {
  return (
    <div role="alert" className="alert alert-warning">
      <span>
        Could not load {source}. Other panels on this page may still be
        complete — this chart was not omitted silently.
      </span>
    </div>
  );
}
