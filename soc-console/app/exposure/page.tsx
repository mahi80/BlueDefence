import { redirect } from "next/navigation";
import ExposureView from "../../components/ExposureView";
import { getPosture } from "../../lib/posture";
import { getSession } from "@/lib/auth";

export const dynamic = "force-dynamic";

export default async function ExposurePage() {
  const session = await getSession();
  if (!session) redirect("/login");
  return <ExposureView result={await getPosture()} session={{ user: session.user, role: session.role }} />;
}
