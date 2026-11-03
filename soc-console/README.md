# AEGIS SOC Console (Next.js + D3)

A standalone command view for the AEGIS autonomous SOC. It renders the swarm's
**blast-radius map** (impacted endpoints, the agent fan-out, and the min-cut
**isolate plan**), the **human-in-the-loop** action queue (approve / reject with
rationale), and the **model-evolution** strip (retrain / promotion proposals).

It is a thin client over the existing ACP dashboard backend — it reads/writes the
same Postgres via the FastAPI endpoints already on `main`:

- `GET /api/soc/chains`, `GET /api/soc/chains/{id}` — evidence chains + blast radius
- `GET /api/approvals`, `POST /api/approvals/{id}/approve|reject` — HITL decisions
- `GET /api/soc/proposals`, `POST /api/soc/proposals/{id}/decide` — model/rule promotion

## Run

```bash
npm install
npm run dev          # http://localhost:3000 — uses bundled fixtures, no backend needed
```

Point it at a real backend:

```bash
AEGIS_API_ORIGIN=http://127.0.0.1:8787 AEGIS_API_KEY=<AEGIS_CONSOLE_TOKEN from aegis.env> npm run dev
```

| Env | Meaning |
|---|---|
| `AEGIS_API_ORIGIN` | The AEGIS host's push receiver (`aegis/ingest/http_push.py`), which serves `/api/soc/chains`, `/api/soc/chains/{id}`, `/api/approvals`, `/api/soc/proposals` from the audit chain and HITL files (`aegis/ingest/console_api.py`). The ACP dashboard's `/api/soc/*` has the same shape and also works. Empty → bundled fixtures ("sample stream" in the header). |
| `NEXT_PUBLIC_AEGIS_USE_FIXTURES` | Force fixtures even when an origin is set (`1`). |
| `AEGIS_API_KEY` | Bearer for server-side calls — `AEGIS_CONSOLE_TOKEN` on the host. Reads work with the read token too; **decisions need the console token**. |

Decisions (`Approve` / `Reject`, model-loop `Promote`) never go browser → backend: `app/api/approvals/[id]/[decision]`
and `app/api/soc/proposals/[id]/decide` check the session cookie, refuse roles that may not decide, then forward
with the key and `X-AEGIS-User: role:user`, which the host writes into the decision row.
| `AEGIS_ASK_URL` | Optional LLM-backed **Agent Q** endpoint. Empty → Q answers deterministically from the chain. |

The browser never talks to the backend: every call goes through a console route handler that checks the
session and adds the key server-side (there is no pass-through rewrite). `AEGIS_CONSOLE_SECRET` (16+ chars)
is **required** in production — the server refuses to sign a session without it. Security headers
(frame-ancestors none, nosniff, HSTS) are set by `next.config.mjs`.

## Auth

The console sits behind a login. Two modes:

| `AEGIS_AUTH_MODE` | Sign-in | For |
|---|---|---|
| `demo` (default) | local id + password (`AEGIS_DEMO_USER` / `_PASSWORD` / `_ROLE`) | demos, local dev — not production |
| `oidc` | single sign-on to the bank IdP (Entra ID / SAML), IdP-group → role via `AEGIS_OIDC_ROLE_MAP` | production |

The session is a signed, httpOnly cookie (`AEGIS_CONSOLE_SECRET` — set a strong value in prod). Roles: `admin` / `cio` / `ciso` / `bu_head` / `analyst`; only the first four may approve a containment action or promote a model. The **backend enforces** every high-impact action and audits who + role + rationale; the console reflects permissions. The OIDC callback's verified `id_token` handling is completed at deployment against the bank's IdP (the route refuses an unverified token path by default).

## Ask Agent Q

**Agent Q** is a living sentinel in the corner (`components/QMascot.tsx`, an original SVG character): it
breathes, blinks, its eyes follow the pointer, its lamp and halo carry the threat level (green calm · amber
suspicious · red malicious with a pulse ring · grey when on the sample stream) and a badge counts pending
approvals. Drag it anywhere — the spot is remembered in the browser — and the chat drawer opens on whichever
side has room; a tap opens Q. Honours `prefers-reduced-motion`. The mascot lets an analyst interrogate the selected detection ("why flagged?",
"what's at risk?", "what should I do?"). It answers **from the evidence chain itself** — verdict,
blast radius (reached assets, crown jewels, choke point), recommended actions, who investigated — so
it never invents facts and works with zero backend. Set `AEGIS_ASK_URL` to forward free-text
questions to the bank's LLM-backed Q (with the detection as context); it falls back to the
deterministic answer if that endpoint is down. See the deploy guide §4g.

## Checks

```bash
npm run typecheck    # tsc --noEmit (the CI gate)
npm run build        # next build
npm run lint         # next lint (dev convenience)
```

## Design

Deep-navy command center; color is the verdict taxonomy (malicious / suspicious /
benign / uncertain) plus the swarm cyan and crown-jewel gold — not decoration.
IBM Plex Sans for UI, IBM Plex Mono for telemetry values. One orchestrated motion:
the swarm fan-out + blast reveal on select. `prefers-reduced-motion` respected.

## Sign-in

Two modes, chosen with `AEGIS_AUTH_MODE`:

| Mode | When | How |
|---|---|---|
| `local` (default) | pilots, labs, the weeks before SSO is wired | named accounts in a JSON users file (`AEGIS_CONSOLE_USERS`, default `.aegis-console-users.json`), scrypt-hashed passwords, one role per account, lock-out for 15 min after 5 failed attempts from one address (account+IP, the IP from `X-Real-IP` set by the proxy — a client-supplied `X-Forwarded-For` cannot reset it) and after 50 failed attempts on the account from anywhere, so a stranger cannot lock an analyst out with five guesses; an unknown account name costs the same scrypt run as a real one; a disabled account or a role change takes effect on the next request, not the next login. Manage with `npm run user -- add <name> <role>` (prompts for the password; 12+ chars), `list`, `disable <name>`, `remove <name>`. With no users file, `AEGIS_DEMO_USER` and `AEGIS_DEMO_PASSWORD` (both required — there is no default password) / `AEGIS_DEMO_ROLE` keep a single demo account; a users file that exists but cannot be read stops sign-in instead of falling back to it. Sign-in, decisions and Ask Q refuse cross-site requests (Origin / Sec-Fetch-Site), and Ask Q reads the detection from the backend by id. |
| `oidc` | production | the bank's identity provider (Entra ID, or any SAML-federated OIDC provider). `AEGIS_OIDC_AUTHORIZE_URL`, `AEGIS_OIDC_CLIENT_ID`, `AEGIS_OIDC_REDIRECT_URI`, and `AEGIS_OIDC_ROLE_MAP="group:role,…"` map IdP groups to console roles. The callback completes the code exchange with **verified** id_tokens at deployment (it answers 501 until that is wired, so no unverified path can reach production). |

Roles: `analyst` (view, propose) · `bu_head`, `ciso`, `cio`, `admin` (may approve containment actions and model promotions). Set `AEGIS_CONSOLE_SECRET` to a long random string — it signs the 8-hour session cookie.
