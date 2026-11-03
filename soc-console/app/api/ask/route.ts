// Ask Agent Q about a detection. If AEGIS_ASK_URL is set, the question + chain context are
// forwarded to the real LLM-backed Q (the one the ACP dashboard already runs) and its answer is
// returned. Otherwise — or if that call fails — we answer deterministically from the chain itself,
// the same way the console does offline. Either way the analyst gets a grounded answer.

import { NextResponse } from "next/server";
import { getChain } from "../../../lib/api";
import { answerLocally } from "../../../lib/ask";
import { getSession } from "../../../lib/auth";
import { askUpstream, sameOrigin } from "../../../lib/origin";
import type { Chain } from "../../../lib/types";

export const runtime = "nodejs";

export async function POST(req: Request) {
  if (!sameOrigin(req.headers)) return NextResponse.json({ error: "cross-site request refused" }, { status: 403 });
  if (!(await getSession())) return NextResponse.json({ error: "not signed in" }, { status: 401 });
  let question = "";
  let chainId = "";
  try {
    const body = await req.json();
    question = String(body?.question ?? "").slice(0, 2000);
    chainId = String(body?.chain_id ?? body?.chain?.chain_id ?? "").slice(0, 200);
  } catch {
    return NextResponse.json({ answer: "I couldn't read that question — try again.", source: "error" }, { status: 400 });
  }
  // The chain is read from the backend by id. The browser used to send the whole chain and Q answered from it,
  // so anyone signed in could have Q "confirm" a verdict, evidence or approval that does not exist (round 3 G6-7).
  let chain: Chain | undefined;
  if (chainId) {
    try {
      chain = (await getChain(chainId)) ?? undefined;
    } catch {
      return NextResponse.json({ answer: "I couldn't load that detection from the SOC backend right now.", source: "error" }, { status: 502 });
    }
  }

  // AEGIS_ASK_KEY only — the console's backend key (AEGIS_API_KEY) can approve actions and never leaves for Q
  const upstream = askUpstream();
  if (upstream) {
    try {
      const r = await fetch(upstream.url, {
        method: "POST",
        headers: upstream.headers,
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
