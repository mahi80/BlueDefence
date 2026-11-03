// Server-side forwarding of analyst decisions to the AEGIS host.
//
// The browser never holds the API key and is never trusted for identity: the signed session cookie
// decides who is acting and whether the role may decide at all; the request is then forwarded to the
// backend with the key and an `X-AEGIS-User` header (role:user) the backend records in the decision row.
import { NextResponse } from "next/server";
import { canDecide, getSession } from "@/lib/auth";
import { sameOrigin } from "@/lib/origin";

const ORIGIN = process.env.AEGIS_API_ORIGIN || "";

export async function forwardDecision(path: string, body: unknown, req?: Request): Promise<NextResponse> {
  if (req && !sameOrigin(req.headers)) return NextResponse.json({ error: "cross-site request refused" }, { status: 403 });
  const s = await getSession();
  if (!s) return NextResponse.json({ error: "not signed in" }, { status: 401 });
  if (!canDecide(s.role)) return NextResponse.json({ error: `role ${s.role} may not decide` }, { status: 403 });
  if (!ORIGIN) return NextResponse.json({ error: "no backend configured (fixture mode)" }, { status: 503 });
  const headers: Record<string, string> = { "Content-Type": "application/json", "X-AEGIS-User": `${s.role}:${s.user}` };
  if (process.env.AEGIS_API_KEY) headers.Authorization = `Bearer ${process.env.AEGIS_API_KEY}`;
  try {
    const r = await fetch(`${ORIGIN}${path}`, { method: "POST", headers, body: JSON.stringify(body ?? {}), cache: "no-store" });
    const text = await r.text();
    let data: unknown = {};
    try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text.slice(0, 200) }; }
    return NextResponse.json(data, { status: r.status });
  } catch (e) {
    return NextResponse.json({ error: `backend unreachable: ${(e as Error).message}` }, { status: 502 });
  }
}
