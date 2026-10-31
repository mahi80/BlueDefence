// Ask Agent Q about a detection. If AEGIS_ASK_URL is set, the question + chain context are
// forwarded to the real LLM-backed Q (the one the ACP dashboard already runs) and its answer is
// returned. Otherwise — or if that call fails — we answer deterministically from the chain itself,
// the same way the console does offline. Either way the analyst gets a grounded answer.

import { NextResponse } from "next/server";
import { answerLocally } from "../../../lib/ask";
import type { Chain } from "../../../lib/types";

export const runtime = "nodejs";

export async function POST(req: Request) {
  let question = "";
  let chain: Chain | undefined;
  try {
    const body = await req.json();
    question = String(body?.question ?? "").slice(0, 2000);
    chain = body?.chain as Chain | undefined;
  } catch {
    return NextResponse.json({ answer: "I couldn't read that question — try again.", source: "error" }, { status: 400 });
  }

  const upstream = process.env.AEGIS_ASK_URL?.trim();
  if (upstream) {
    try {
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (process.env.AEGIS_API_KEY) headers["X-API-Key"] = process.env.AEGIS_API_KEY;
      const r = await fetch(upstream, {
        method: "POST",
        headers,
        body: JSON.stringify({ question, alert_id: chain?.alert_id, chain_id: chain?.chain_id, context: chain }),
        signal: AbortSignal.timeout(20000),
      });
      if (r.ok) {
        const data = await r.json().catch(() => ({}));
        // tolerate the common shapes the Q backend might return
        const answer = data?.answer ?? data?.text ?? data?.response ?? data?.message;
        if (typeof answer === "string" && answer.trim()) {
          return NextResponse.json({ answer, source: "agent-q" });
        }
      }
      // fall through to the local answerer on a non-ok / unexpected shape
    } catch {
      /* upstream unreachable → local answer below */
    }
  }

  return NextResponse.json({ answer: answerLocally(question, chain), source: "local" });
}
