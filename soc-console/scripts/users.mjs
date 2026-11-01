#!/usr/bin/env node
// Manage the console's local accounts:  npm run user -- add <name> <role> | list | disable <name> | remove <name>
// Roles: admin, cio, ciso, bu_head (may approve actions) · analyst (read + propose).
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import readline from "node:readline";

const ROLES = ["admin", "cio", "ciso", "bu_head", "analyst"];
const file = process.env.AEGIS_CONSOLE_USERS || path.join(process.cwd(), ".aegis-console-users.json");
const load = () => { try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch { return { users: {} }; } };
const save = (u) => { fs.writeFileSync(file + ".tmp", JSON.stringify(u, null, 2) + "\n", { mode: 0o600 }); fs.renameSync(file + ".tmp", file); };
const hash = (pw) => { const salt = crypto.randomBytes(16); const key = crypto.scryptSync(pw, salt, 32, { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }); return `scrypt$${salt.toString("base64url")}$${key.toString("base64url")}`; };
const ask = (q) => new Promise((res) => { const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true }); process.stdout.write(q); rl._writeToOutput = () => {}; rl.question("", (a) => { rl.close(); process.stdout.write("\n"); res(a); }); });

const [cmd, name, role] = process.argv.slice(2);
const u = load();
if (cmd === "list") {
  for (const [n, r] of Object.entries(u.users)) console.log(`${n.padEnd(24)} ${r.role.padEnd(8)} ${r.disabled ? "disabled" : "active"}`);
} else if (cmd === "add") {
  if (!name || !/^[a-z0-9][a-z0-9._@-]{1,63}$/i.test(name)) { console.error("usage: add <name> <role> — name: letters, digits, . _ @ -"); process.exit(2); }
  if (!ROLES.includes(role)) { console.error(`role must be one of ${ROLES.join(", ")}`); process.exit(2); }
  const pw = process.env.AEGIS_USER_PASSWORD || (await ask(`password for ${name}: `));
  if (pw.length < 12) { console.error("password must be at least 12 characters"); process.exit(2); }
  u.users[name] = { role, hash: hash(pw) };
  save(u); console.log(`${name} (${role}) saved to ${file}`);
} else if (cmd === "disable" || cmd === "remove") {
  if (!u.users[name]) { console.error("no such user"); process.exit(2); }
  if (cmd === "remove") delete u.users[name]; else u.users[name].disabled = true;
  save(u); console.log(`${name} ${cmd}d`);
} else {
  console.log("usage: npm run user -- add <name> <role> | list | disable <name> | remove <name>");
}
