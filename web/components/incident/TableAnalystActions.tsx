import { formatUtc } from "@/lib/format";
import type { AnalystActionItem } from "@/lib/types";

type TableAnalystActionsProps = {
  actions: AnalystActionItem[];
};

export function TableAnalystActions({ actions }: TableAnalystActionsProps) {
  if (actions.length === 0) {
    return (
      <div role="alert" className="alert">
        <span>No analyst actions recorded for this incident.</span>
      </div>
    );
  }

  return (
    <div className="fft-paper-panel overflow-x-auto">
      <table className="table table-sm">
        <thead>
          <tr>
            <th>Created (UTC)</th>
            <th>Operator</th>
            <th>Action</th>
            <th>Anomaly</th>
            <th>Note</th>
          </tr>
        </thead>
        <tbody>
          {actions.map((row) => (
            <tr key={row.action_id}>
              <td className="font-mono text-sm">{formatUtc(row.created_at)}</td>
              <td className="font-mono text-sm">{row.operator_label}</td>
              <td>
                <span className="badge badge-outline">{row.action}</span>
              </td>
              <td className="font-mono text-sm">{row.anomaly_id || "—"}</td>
              <td className="max-w-md text-sm">{row.note || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
