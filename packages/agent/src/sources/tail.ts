import { watch, statSync, openSync, readSync, closeSync } from "node:fs";
import { EventEmitter } from "node:events";

export class Tailer extends EventEmitter {
  private pos = 0;
  private buf = "";
  private watcher?: ReturnType<typeof watch>;
  private poll?: NodeJS.Timeout;
  private inode: number | null = null;
  private closed = false;

  constructor(
    private path: string,
    private pollMs = 2000,
  ) {
    super();
  }

  start(fromEnd = true): void {
    const st = this.statOrNull();
    this.pos = fromEnd && st ? st.size : 0;
    this.inode = st ? st.ino : null;
    this.arm();
    this.poll = setInterval(() => this.check(), this.pollMs);
    this.poll.unref?.();
    this.pump();
  }

  private statOrNull(): { size: number; ino: number } | null {
    try {
      const s = statSync(this.path);
      return { size: s.size, ino: s.ino };
    } catch {
      return null;
    }
  }

  private arm(): void {
    this.watcher?.close();
    this.watcher = undefined;
    try {
      this.watcher = watch(this.path, { persistent: false }, () => this.pump());
    } catch {
      return;
    }
    this.watcher.on("error", () => {
      this.watcher?.close();
      this.watcher = undefined;
    });
  }

  private check(): void {
    if (this.closed) return;
    const st = this.statOrNull();
    if (!st) {
      this.watcher?.close();
      this.watcher = undefined;
      return;
    }
    if (this.inode !== null && st.ino !== this.inode) {
      this.inode = st.ino;
      this.pos = 0;
      this.buf = "";
      this.arm();
    } else if (!this.watcher) {
      this.inode = st.ino;
      this.pos = 0;
      this.arm();
    }
    this.pump();
  }

  private pump(): void {
    if (this.closed) return;
    const st = this.statOrNull();
    if (!st) return;
    if (st.size < this.pos) this.pos = 0;
    if (st.size === this.pos) return;

    let fd: number;
    try {
      fd = openSync(this.path, "r");
    } catch {
      return;
    }
    try {
      const len = st.size - this.pos;
      const chunk = Buffer.allocUnsafe(len);
      const read = readSync(fd, chunk, 0, len, this.pos);
      this.pos += read;
      this.buf += chunk.subarray(0, read).toString("utf8");
    } catch {
      return;
    } finally {
      closeSync(fd);
    }

    let nl: number;
    while ((nl = this.buf.indexOf("\n")) !== -1) {
      const line = this.buf.slice(0, nl).replace(/\r$/, "");
      this.buf = this.buf.slice(nl + 1);
      if (line) this.emit("line", line);
    }
  }

  stop(): void {
    this.closed = true;
    this.watcher?.close();
    if (this.poll) clearInterval(this.poll);
  }
}
