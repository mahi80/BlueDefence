import subprocess, json, pathlib
V = pathlib.Path(__file__).parent
M = "/tmp/claude-0/-home-claude/8362406c-c67e-52fe-a4e8-721a9bb1f7d0/scratchpad/tts/vits-piper-en_US-amy-medium/en_US-amy-medium.onnx"
lines = [
 "BlueDefence AEGIS is an autonomous security operations centre that runs inside the bank, and shows its work.",
 "Here is the problem it solves. One fibre is cut. Fifty-three alarms light up across every console. The analyst has twenty minutes, and none of those alarms says what actually happened.",
 "Step one. Everything comes in through one receiver: web application firewall logs, Sentinel or Splunk, endpoint detection, network syslog and topology, flow telemetry, even Kafka. It sits on top of what you already run. Nothing leaves the bank's network.",
 "Step two. Topology-aware correlation turns the storm into one incident. AEGIS knows which switches sit behind which uplink, where the redundant paths are, how many users each switch carries, and whether a configuration was pushed minutes ago without a change ticket. Fifty-three alarms in. One root cause out.",
 "Step three. Triage. The orchestrator fans out a swarm of workers, and each one reports back. I O C extract finds a bearer token the bank's identity provider never signed. Intel enrich places the source address on two threat feeds as a forged-token command server. Blast radius traces the path from the edge to the ledger host, one hop from the core database. Log hunt finds a service account logging in from a host it has never used. Deception check confirms no honeytoken was touched yet. A model the bank hosts on its own hardware weighs all of it: malicious, with the techniques named. A reviewer from a different model family votes; if it disagrees, a human decides. Every finding is hash-chained into the evidence.",
 "Before anyone decides, they sign in. Today that is a named local account with a scrypt-hashed password and a role: analyst, business-unit head, CISO, CIO or admin. Only the senior roles can approve a containment action. In production the console hands sign-in to the bank's identity provider over OIDC, with Entra ID or SAML groups mapped to those same roles.",
 "This is the console. On the left, incidents, most severe first, with what the swarm proposes. In the centre, why Agent Q flagged it: every worker's finding, strongest first, and a button to ask it why. Agent Q itself lives in the corner, and it is alive: drag it wherever you like, tap it, and ask. On the right, the attack path from the alert through each hop to the crown jewels, with the isolate plan dashed. At the bottom, the decision: the CISO writes a rationale and approves isolating the ledger host. Then an analyst signs in and sees the same case, but can only watch — her role is view-only.",
 "Step four. Response, with a human in the loop. Reversible actions run on their own: enrich, escalate, block a known-bad address. Irreversible ones, like rolling back a core switch or revoking a user's sessions, wait for an analyst. Every connector starts in shadow mode, proposing but never executing, until its shadow report agrees with your team.",
 "Step five. Prove it. Every decision lands in an append-only, tamper-evident audit log and in the ACP governance dashboard, under the same policies the bank applies to all its AI agents. Who decided what, on which evidence, approved by whom, ready for the regulator.",
 "The Community edition is free for two years, and the brain gets smarter from every installation. What leaves the bank is scrubbed evidence chains and analyst decisions: pseudonymised, salted, and checked by a privacy gate that refuses e-mails, addresses, card and account numbers. What comes back are signed model updates, like antivirus definitions: verified, staged, and reversible.",
 "Installation is one command on a Linux host. With no host yet, one terraform apply stands up an all-AWS shadow pilot: a decoy behind AWS WAF, feeding this same console. Wire a feed, and the service appears in a fleet view with its standing, contribution ratio and code attestation, so a silent or tampered install is visible the same day.",
 "Fewer alarms. Faster decisions. Evidence for every one of them. BlueDefence, on GitHub.",
]
meta = []
for i, text in enumerate(lines, 1):
    wav = V / "vo" / f"scene{i:02d}.wav"
    subprocess.run(["piper", "-m", M, "-f", str(wav), "--length-scale", "1.05", "--sentence-silence", "0.35"], input=text.encode(), check=True, capture_output=True)
    d = float(subprocess.check_output(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", wav]))
    meta.append({"scene": i, "dur": d})
    print(i, round(d, 1))
json.dump(meta, open(V / "meta.json", "w"))
print("total", round(sum(m["dur"] for m in meta), 1))
