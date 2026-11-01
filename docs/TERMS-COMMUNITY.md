# BlueDefence Community Edition — terms (summary for the licence record)

**Free for 2 years, per installation.** The model runs at your site on open weights (Qwen / Mistral / Llama);
BlueDefence never receives your logs. In return the installation contributes **derived security telemetry**
so that every Community installation benefits from a brain trained on all of them.

| Topic | Term |
|---|---|
| Term | 730 days from activation, one installation per licence, up to 3 installations per organisation domain |
| Token | the signed licence file is valid 30 days and renews automatically while the installation is in good standing |
| Good standing | daily heartbeat present; contributions track the chains the installation writes (ratio ≥ 0.5 over 30 days); code fingerprint matches a published release; capture and contribution not disabled |
| What is contributed | scrubbed evidence chains (verdict, confidence, evidence *types* and weights, action types, HITL outcome, timing, fault/attack class), the alert *shape* with every identity pseudonymised (salted, per installation), analysts' approve / reject / correction decisions |
| What is never contributed | raw logs or payloads, real IP addresses, hostnames, user names, e-mail addresses, account or card numbers, customer names, device configurations, anything the privacy gate detects (the bundle is then not sent at all) |
| Transparency | `python -m aegis.dataset contrib --out bundle.json.gz` writes exactly what would be sent; the scrubber and gate are open source in this repository |
| Use of contributions | training and evaluation of BlueDefence detection models and rules; aggregated, never resold, never attributed to an organisation |
| Withdrawal | stop contributing at any time; the token then lapses within 30 days (+14 days grace) and the installation continues in evaluation mode (shadow enforcement, 100 devices); a paid licence lifts the obligation |
| Circumvention | modifying the software to suppress capture or contribution while keeping Community features terminates the licence |
| Data residency | the contribution bucket is in the AWS region the licence service is deployed to; a Mumbai (ap-south-1) deployment is available on request |
