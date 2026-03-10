const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";

const defaultHeaders = (tenant = "default", user = "admin") => ({
  "Content-Type": "application/json",
  "x-tenant-id": tenant,
  "x-user-id": user,
  "x-roles": "admin",
});

// ── Alerts ────────────────────────────────────────────────────────────────────

export async function listAlerts(tenant = "default") {
  const res = await fetch(`${BASE}/api/v1/alerts`, {
    headers: defaultHeaders(tenant),
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`listAlerts: ${res.status}`);
  return res.json();
}

// ── Rules ─────────────────────────────────────────────────────────────────────

export async function listRules(tenant = "default") {
  const res = await fetch(`${BASE}/api/v1/rules`, {
    headers: defaultHeaders(tenant),
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`listRules: ${res.status}`);
  return res.json();
}

export async function createRule(tenant = "default", body: object) {
  const res = await fetch(`${BASE}/api/v1/rules`, {
    method: "POST",
    headers: defaultHeaders(tenant),
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`createRule: ${res.status}`);
  return res.json();
}

export async function deleteRule(tenant = "default", id: string) {
  const res = await fetch(`${BASE}/api/v1/rules/${id}`, {
    method: "DELETE",
    headers: defaultHeaders(tenant),
  });
  if (!res.ok) throw new Error(`deleteRule: ${res.status}`);
  return res.json();
}

// ── Coverage ──────────────────────────────────────────────────────────────────

export async function getCoverage(tenant = "default") {
  const res = await fetch(`${BASE}/api/v1/coverage`, {
    headers: defaultHeaders(tenant),
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`getCoverage: ${res.status}`);
  return res.json();
}

// ── NLQ ───────────────────────────────────────────────────────────────────────

export async function nlqSearch(tenant = "default", query: string) {
  const res = await fetch(`${BASE}/api/v1/events/nlq`, {
    method: "POST",
    headers: defaultHeaders(tenant),
    body: JSON.stringify({ query }),
  });
  if (!res.ok) throw new Error(`nlqSearch: ${res.status}`);
  return res.json();
}

// ── Cases ─────────────────────────────────────────────────────────────────────

export async function listCases(tenant = "default") {
  const res = await fetch(`${BASE}/api/v1/cases`, {
    headers: defaultHeaders(tenant),
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`listCases: ${res.status}`);
  return res.json();
}
