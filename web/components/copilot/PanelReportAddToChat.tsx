"use client";

import { ButtonAddToChat } from "@/components/copilot/ButtonAddToChat";
import { MAX_ATTACHMENT_CHARS } from "@/lib/copilot";

type PanelReportAddToChatProps = {
  filename: string;
  incidentId: string;
  markdown: string;
};

export function PanelReportAddToChat({
  filename,
  incidentId,
  markdown,
}: PanelReportAddToChatProps) {
  const excerpt =
    markdown.length > MAX_ATTACHMENT_CHARS
      ? `${markdown.slice(0, MAX_ATTACHMENT_CHARS)}…`
      : markdown;
  return (
    <ButtonAddToChat
      label={`Report: ${filename}`}
      text={excerpt}
      incidentId={incidentId}
      route={`/reports/${filename}`}
      className="btn btn-ghost btn-sm"
    />
  );
}
