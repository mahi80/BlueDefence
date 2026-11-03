import { forwardDecision } from "@/lib/decide";

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  const body = await req.json().catch(() => ({}));
  return forwardDecision(`/api/soc/proposals/${encodeURIComponent(id)}/decide`, body, req);
}
