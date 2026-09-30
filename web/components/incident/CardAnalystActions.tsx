import { FormAnalystAction } from "@/components/incident/FormAnalystAction";
import { TableAnalystActions } from "@/components/incident/TableAnalystActions";
import type { AnalystActionItem } from "@/lib/types";

type CardAnalystActionsProps = {
  incidentId: string;
  actions: AnalystActionItem[];
  defaultOperatorLabel: string;
};

export function CardAnalystActions({
  incidentId,
  actions,
  defaultOperatorLabel,
}: CardAnalystActionsProps) {
  return (
    <section className="flex flex-col gap-3">
      <h2 className="text-lg font-semibold">Analyst actions</h2>
      <p className="text-sm opacity-70">
        Append-only warehouse log. Undo is a compensating reopen row, not
        delete. Operator is a local label (no login); default is{" "}
        <span className="font-mono">{defaultOperatorLabel}</span>.
      </p>
      <TableAnalystActions actions={actions} />
      <FormAnalystAction
        incidentId={incidentId}
        defaultOperatorLabel={defaultOperatorLabel}
        mode="incident"
      />
    </section>
  );
}
