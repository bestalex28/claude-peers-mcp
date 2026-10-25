/**
 * Broker authentication (ADAMX S8, 2026-10-25).
 *
 * Plain English: the broker on 127.0.0.1:7899 used to accept ANY local request - any program on the machine, or a web page
 * open in a browser here (a plain-text POST needs no CORS preflight), could inject a message straight into a Captain session.
 * Now every request must carry the secret from ~/.claude-peers.token (0600, created by the broker on first start), and any
 * request that carries a browser Origin header is refused outright.
 */
import { existsSync, readFileSync, writeFileSync, chmodSync, statSync } from "node:fs";
import { randomBytes, timingSafeEqual } from "node:crypto";

export const TOKEN_FILE = process.env.CLAUDE_PEERS_TOKEN_FILE ?? `${process.env.HOME}/.claude-peers.token`;
export const TOKEN_HEADER = "x-peers-token";

function readToken(): string {
  const st = statSync(TOKEN_FILE);
  if ((st.mode & 0o077) !== 0) throw new Error(`${TOKEN_FILE} must be mode 0600`);
  const t = readFileSync(TOKEN_FILE, "utf8").trim();
  if (t.length < 32) throw new Error(`${TOKEN_FILE} is too short`);
  return t;
}

/** Broker side: create the token once (0600), then always read it from the file. */
export function loadOrCreateToken(): string {
  if (!existsSync(TOKEN_FILE)) {
    writeFileSync(TOKEN_FILE, randomBytes(32).toString("hex") + "\n", { mode: 0o600, flag: "wx" });
    chmodSync(TOKEN_FILE, 0o600);
  }
  return readToken();
}

/** Client side (MCP server, CLI): read only - a missing token means the broker never started. */
export function clientToken(): string {
  return readToken();
}

export function tokenOk(got: string | null, want: string): boolean {
  if (!got) return false;
  const a = Buffer.from(got), b = Buffer.from(want);
  return a.length === b.length && timingSafeEqual(a, b);
}
