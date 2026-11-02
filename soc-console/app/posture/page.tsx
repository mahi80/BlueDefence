import { redirect } from "next/navigation";
import PostureView from "../../components/PostureView";
import { getPosture } from "../../lib/posture";
import { getSession } from "@/lib/auth";

export const dynamic = "force-dynamic";

export default async function PosturePage() {
  const session = await getSession();
  if (!session) redirect("/login");
  const result = await getPosture();
  return <PostureView result={result} session={{ user: session.user, role: session.role }} />;
}
