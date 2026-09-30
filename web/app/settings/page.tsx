import { PageHeader } from "@/components/layout/PageHeader";
import { PanelThemeSelect } from "@/components/theme/PanelThemeSelect";

export default function SettingsPage() {
  return (
    <div className="fft-page">
      <PageHeader
        eyebrow="Preferences"
        title="Settings"
        blurb="Local UI preferences for this browser. Nothing is sent to the API."
      />
      <PanelThemeSelect />
    </div>
  );
}
