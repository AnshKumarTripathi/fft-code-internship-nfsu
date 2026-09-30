import { FooterLocalTrust } from "@/components/layout/FooterLocalTrust";
import { NavDrawer } from "@/components/layout/NavDrawer";
import { NavRail } from "@/components/layout/NavRail";
import { PanelCopilot } from "@/components/copilot/PanelCopilot";
import { PromptSelectionAddToChat } from "@/components/copilot/PromptSelectionAddToChat";
import { ProviderCopilot } from "@/components/copilot/ProviderCopilot";
import { ProviderTheme } from "@/components/theme/ProviderTheme";
import Link from "next/link";

type ShellAppProps = {
  children: React.ReactNode;
};

export function ShellApp({ children }: ShellAppProps) {
  return (
    <ProviderTheme>
      <ProviderCopilot>
        <div className="flex min-h-full flex-1">
          <NavRail />
          <div className="flex min-w-0 flex-1 flex-col">
            <header className="flex items-center gap-2 border-b border-base-300 bg-base-100 px-4 py-2 md:hidden">
              <NavDrawer />
              <Link
                href="/"
                className="text-base font-semibold tracking-tight text-base-content"
              >
                Log Anomaly
              </Link>
            </header>
            <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 lg:px-8">
              {children}
            </main>
            <FooterLocalTrust />
          </div>
        </div>
        <PromptSelectionAddToChat />
        <PanelCopilot />
      </ProviderCopilot>
    </ProviderTheme>
  );
}
