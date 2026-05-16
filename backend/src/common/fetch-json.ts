export async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, init);
  const text = await response.text();
  const parsed = text ? JSON.parse(text) : {};
  if (!response.ok) {
    const message = typeof parsed?.error === "object" ? parsed.error.message : response.statusText;
    throw new Error(`${response.status} ${message}`);
  }
  return parsed as T;
}
