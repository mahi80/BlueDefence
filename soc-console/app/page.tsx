import { redirect } from "next/navigation";
import Console from "../components/Console";
import { getRecentChains, listApprovals, listProposals, isFixtureMode, settle } from "../lib/api";
import type { Approval, Chain, Proposal } from "../lib/types";
import { getSession, canDecide } from "@/lib/auth";

// Always render against the latest SOC state (or fixtures when no backend is set).
export const dynamic = "force-dynamic";

export default async function Page() {
  const session = await getSession();
  if (!session) redirect("/login");

  // a failed read shows as an error on the page, never as "live, 0 pending"
  const { values: [chains, approvals, proposals], errors } = await settle<[Chain[], Approval[], Proposal[]]>(
    [getRecentChains(), listApprovals(), listProposals()], [[], [], []]);
  return (
    <Console
      chains={chains}
      approvals={approvals}
      proposals={proposals}
      fixtureMode={isFixtureMode}
      backendError={errors.length ? errors.join(" · ") : null}
      session={{ user: session.user, role: session.role }}
      canDecide={canDecide(session.role)}
    />
  );
}
