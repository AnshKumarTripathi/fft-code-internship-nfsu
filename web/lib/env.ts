export function apiBaseUrl(): string {
  const raw = process.env.NEXT_PUBLIC_API_BASE?.trim();
  if (!raw) {
    return "http://127.0.0.1:8000";
  }
  return raw.replace(/\/+$/, "");
}
