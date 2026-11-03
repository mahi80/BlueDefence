"use client";

import { useState, type FormEvent } from "react";

export default function LoginPage() {
  const mode = process.env.NEXT_PUBLIC_AEGIS_AUTH_MODE === "oidc" ? "oidc" : "local";
  const [user, setUser] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setErr("");
    setBusy(true);
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user, password }),
      });
      if (res.ok) {
        window.location.href = "/";
        return;
      }
      const j = await res.json().catch(() => ({}));
      setErr(j.error || "Sign-in failed.");
    } catch {
      setErr("Sign-in failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-wrap">
      <div className="login-card">
        <div className="login-brand">
          <b>AEGIS</b> SOC
        </div>
        <p className="login-sub">Autonomous defense console</p>
        {mode === "oidc" ? (
          <>
            <a className="login-sso" href="/api/auth/oidc/start">
              Sign in with your organization
            </a>
            <p className="login-note">Single sign-on through your identity provider (Entra ID / SAML).</p>
          </>
        ) : (
          <form onSubmit={submit} className="login-form">
            <label htmlFor="user">
              Username
              <input id="user" value={user} onChange={(e) => setUser(e.target.value)} autoComplete="username" autoFocus />
            </label>
            <label htmlFor="password">
              Password
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
              />
            </label>
            {err && <div className="login-err">{err}</div>}
            <button className="login-btn" disabled={busy} type="submit">
              {busy ? "Signing in…" : "Sign in"}
            </button>
            <p className="login-note">Local accounts (managed with <code>npm run user</code>). Production uses your organization&rsquo;s single sign-on (Entra ID / SAML).</p>
          </form>
        )}
      </div>
    </div>
  );
}
