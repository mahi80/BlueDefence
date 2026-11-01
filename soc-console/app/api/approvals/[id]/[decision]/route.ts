import { NextResponse } from "next/server";
import { forwardDecision } from "@/lib/decide";

export async function POST(req: Request, ctx: { params: Promise<{ id: string; decision: string }> }) {
  const { id, decision } = await ctx.params;
  if (decision !== "approve" && decision !== "reject") return NextResponse.json({ error: "approve or reject" }, { status: 404 });
  const body = await req.json().catch(() => ({}));
  return forwardDecision(`/api/approvals/${encodeURIComponent(id)}/${decision}`, body);
}
