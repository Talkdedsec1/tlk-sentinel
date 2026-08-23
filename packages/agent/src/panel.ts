import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { brandTag, isValidIp, type Lang, type Threat } from "@tlk-sentinel/core";
import type { Store } from "./store.js";
import { dashboardHtml } from "./panel-html.js";

export interface PanelOptions {
  store: Store;
  host: string;
  port: number;
  token: string | null;
  lang: Lang;
  onUnban: (ip: string) => void;
  onBan: (ip: string, seconds: number) => void;
}

interface Client {
  res: ServerResponse;
}

export class Panel {
  private clients = new Set<Client>();

  constructor(private opt: PanelOptions) {}

  start(): void {
    const server = createServer((req, res) => this.route(req, res));
    server.listen(this.opt.port, this.opt.host);
  }

  push(threat: Threat, banned: boolean): void {
    const data = JSON.stringify({ threat, banned });
    for (const c of this.clients) {
      c.res.write(`data: ${data}\n\n`);
    }
  }

  private authed(req: IncomingMessage): boolean {
    if (!this.opt.token) return true;
    const url = new URL(req.url ?? "/", "http://x");
    const q = url.searchParams.get("token");
    const h = req.headers["x-panel-token"];
    return q === this.opt.token || h === this.opt.token;
  }

  private async route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", "http://x");
    if (!this.authed(req)) {
      res.writeHead(401).end("unauthorized");
      return;
    }
    const p = url.pathname;

    if (p === "/") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", ...SAFE_HEADERS });
      res.end(dashboardHtml(this.opt.lang, brandTag()));
      return;
    }
    if (p === "/api/stats") {
      return this.json(res, this.opt.store.stats(24 * 3600 * 1000));
    }
    if (p === "/api/threats") {
      return this.json(res, this.opt.store.recentThreats(150));
    }
    if (p === "/api/bans") {
      return this.json(res, this.opt.store.activeBans());
    }
    if (p === "/api/unban" && req.method === "POST") {
      const body = await readBody(req);
      if (!isValidIp(body.ip)) return this.json(res, { ok: false, error: "invalid ip" }, 400);
      this.opt.onUnban(body.ip);
      this.opt.store.removeBan(body.ip);
      return this.json(res, { ok: true });
    }
    if (p === "/api/ban" && req.method === "POST") {
      const body = await readBody(req);
      if (!isValidIp(body.ip)) return this.json(res, { ok: false, error: "invalid ip" }, 400);
      const seconds = Number(body.seconds ?? 86400);
      if (!Number.isFinite(seconds) || seconds <= 0 || seconds > 31536000) {
        return this.json(res, { ok: false, error: "invalid duration" }, 400);
      }
      this.opt.onBan(body.ip, seconds);
      return this.json(res, { ok: true });
    }
    if (p === "/api/stream") {
      res.writeHead(200, {
        "content-type": "text/event-stream",
        "cache-control": "no-cache",
        connection: "keep-alive",
      });
      res.write(": connected\n\n");
      const client: Client = { res };
      this.clients.add(client);
      req.on("close", () => this.clients.delete(client));
      return;
    }
    res.writeHead(404).end("not found");
  }

  private json(res: ServerResponse, data: unknown, status = 200): void {
    res.writeHead(status, { "content-type": "application/json", ...SAFE_HEADERS });
    res.end(JSON.stringify(data));
  }
}

const SAFE_HEADERS = {
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  "cache-control": "no-store",
};

const MAX_BODY = 64 * 1024;

async function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req) {
    const buf = c as Buffer;
    size += buf.length;
    if (size > MAX_BODY) {
      req.destroy();
      return {};
    }
    chunks.push(buf);
  }
  try {
    const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
    return parsed !== null && typeof parsed === "object" ? (parsed as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}
