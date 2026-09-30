"use client";

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import type { CopilotAttachment, CopilotChatMessage } from "@/lib/types";
import { MAX_ATTACHMENT_CHARS } from "@/lib/copilot";

export type CopilotAttachmentChip = CopilotAttachment & {
  id: string;
};

type CopilotContextValue = {
  isOpen: boolean;
  openPanel: () => void;
  closePanel: () => void;
  togglePanel: () => void;
  attachments: CopilotAttachmentChip[];
  addAttachment: (attachment: CopilotAttachment) => void;
  removeAttachment: (id: string) => void;
  clearAttachments: () => void;
  messages: CopilotChatMessage[];
  setMessages: React.Dispatch<React.SetStateAction<CopilotChatMessage[]>>;
};

const CopilotContext = createContext<CopilotContextValue | null>(null);

function newId(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `att-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function capText(text: string | null | undefined): string {
  const raw = (text ?? "").trim();
  if (raw.length <= MAX_ATTACHMENT_CHARS) {
    return raw;
  }
  return raw.slice(0, MAX_ATTACHMENT_CHARS);
}

export function ProviderCopilot({ children }: { children: ReactNode }) {
  const [isOpen, setIsOpen] = useState(false);
  const [attachments, setAttachments] = useState<CopilotAttachmentChip[]>([]);
  const [messages, setMessages] = useState<CopilotChatMessage[]>([]);

  const openPanel = useCallback(() => setIsOpen(true), []);
  const closePanel = useCallback(() => setIsOpen(false), []);
  const togglePanel = useCallback(() => setIsOpen((prev) => !prev), []);

  const addAttachment = useCallback((attachment: CopilotAttachment) => {
    const chip: CopilotAttachmentChip = {
      ...attachment,
      kind: attachment.kind || "page_selection",
      text: capText(attachment.text),
      id: newId(),
    };
    setAttachments((prev) => [...prev, chip]);
    setIsOpen(true);
  }, []);

  const removeAttachment = useCallback((id: string) => {
    setAttachments((prev) => prev.filter((item) => item.id !== id));
  }, []);

  const clearAttachments = useCallback(() => setAttachments([]), []);

  const value = useMemo(
    () => ({
      isOpen,
      openPanel,
      closePanel,
      togglePanel,
      attachments,
      addAttachment,
      removeAttachment,
      clearAttachments,
      messages,
      setMessages,
    }),
    [
      isOpen,
      openPanel,
      closePanel,
      togglePanel,
      attachments,
      addAttachment,
      removeAttachment,
      clearAttachments,
      messages,
    ],
  );

  return (
    <CopilotContext.Provider value={value}>{children}</CopilotContext.Provider>
  );
}

export function useCopilot(): CopilotContextValue {
  const ctx = useContext(CopilotContext);
  if (!ctx) {
    throw new Error("useCopilot must be used within ProviderCopilot");
  }
  return ctx;
}
