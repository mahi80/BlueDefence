import { redirect } from "next/navigation";
import Console from "../components/Console";
import { getRecentChains, listApprovals, listProposals, isFixtureMode, settle } from "../lib/api";
import type { Approval, Chain, Proposal } from "../lib/types";
import { getSession, canDecide } from "@/lib/auth";

// Always render against the latest SOC state (or fixtures when no backend is set).
export const dynamic = "force-dynamic";

/** Read errors plus incidents whose details could not be read (round 7 U-4): never a silent green "live". */
function backendErrors(errors: string[], chains: Chain[]): string | null {
  const partial = chains.filter((c) => c.partial).length;
  const all = partial ? [...errors, `${partial} incident detail${partial > 1 ? "s" : ""} unavailable`] : errors;
  return all.length ? all.join(" · ") : null;
}

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
      backendError={backendErrors(errors, chains)}
      session={{ user: session.user, role: session.role }}
      canDecide={canDecide(session.role)}
    />
  );
}
