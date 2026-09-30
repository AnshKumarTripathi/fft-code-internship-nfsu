"use client";

import { usePathname } from "next/navigation";
import { useCopilot } from "@/components/copilot/ProviderCopilot";

type ButtonAddToChatProps = {
  label: string;
  text: string;
  incidentId?: string | null;
  entityId?: string | null;
  slug?: string | null;
  route?: string | null;
  className?: string;
};

export function ButtonAddToChat({
  label,
  text,
  incidentId,
  entityId,
  slug,
  route,
  className,
}: ButtonAddToChatProps) {
  const pathname = usePathname();
  const { addAttachment } = useCopilot();

  return (
    <button
      type="button"
      className={className ?? "btn btn-ghost btn-xs"}
      onClick={() =>
        addAttachment({
          kind: "page_selection",
          label,
          text,
          incident_id: incidentId ?? null,
          entity_id: entityId ?? null,
          slug: slug ?? null,
          route: route ?? pathname,
        })
      }
    >
      Add to chat
    </button>
  );
}
