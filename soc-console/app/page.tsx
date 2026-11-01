import { redirect } from "next/navigation";
import Console from "../components/Console";
import { getRecentChains, listApprovals, listProposals, isFixtureMode, lastBackendError } from "../lib/api";
import { getSession, canDecide } from "@/lib/auth";

// Always render against the latest SOC state (or fixtures when no backend is set).
export const dynamic = "force-dynamic";

export default async function Page() {
  const session = await getSession();
  if (!session) redirect("/login");

  const [chains, approvals, proposals] = await Promise.all([getRecentChains(), listApprovals(), listProposals()]);
  return (
    <Console
      chains={chains}
      approvals={approvals}
      proposals={proposals}
      fixtureMode={isFixtureMode}
      backendError={lastBackendError()}
      session={{ user: session.user, role: session.role }}
      canDecide={canDecide(session.role)}
    />
  );
}
