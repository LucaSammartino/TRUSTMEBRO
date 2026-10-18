// Terminal dashboard for `pool watch`: a pure function from Activity to text.
import type { Activity } from "./activity.ts";

/** Text that came from other people: drop escape sequences and control characters before it reaches a terminal. */
export function clean(text: unknown): string {
  return String(text ?? "")
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "") // CSI sequences
    .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?/g, "") // OSC sequences
    .replace(/\x1b[P^_X][^\x1b]*(?:\x1b\\)?/g, "") // DCS / PM / APC / SOS
    .replace(/[\r\n\t]+/g, " ")
    .replace(/[\x00-\x1f\x7f-\x9f]/g, "");
}

const COLORS = { green: 32, yellow: 33, red: 31, cyan: 36, dim: 2, bold: 1 } as const;

function clip(text: string, width: number): string {
  return text.length <= width ? text : width <= 3 ? text.slice(0, Math.max(width, 0)) : text.slice(0, width - 3) + "...";
}

function hhmm(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "--:--";
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}

export function renderActivity(a: Activity, opts: { width?: number; color?: boolean } = {}): string {
  const width = Math.max(20, Math.floor(opts.width ?? 80));
  const paint = (style: keyof typeof COLORS, text: string) => (opts.color && text ? `\x1b[${COLORS[style]}m${text}\x1b[0m` : text);
  const lines: string[] = [];
  const add = (text: string, style?: keyof typeof COLORS) => {
    const t = clip(text, width);
    lines.push(style ? paint(style, t) : t);
  };

  const t = a.totals;
  const percent = Math.max(0, Math.min(100, Math.round(Number(t.percentDone) || 0)));
  add(clean(a.project), "bold");

  const label = ` ${String(percent).padStart(3)}%`;
  const inner = Math.max(5, width - 2 - label.length);
  const filled = Math.round((inner * percent) / 100);
  const bar = `[${"#".repeat(filled)}${".".repeat(inner - filled)}]${label}`;
  const barPlain = clip(bar, width);
  lines.push(opts.color ? barPlain.replace(/#+/, (m) => paint("green", m)) : barPlain);

  add(`${t.done} of ${t.functions} functions done, ${t.inProgress} in progress, ${t.waiting} waiting`);
  const r = a.results;
  add(`Results: ${r.trusted} trusted, ${r.pending} pending, ${r.hints} hints, ${r.rejected} rejected`);
  if (a.throughputPerHour) add(`Last hour: ${a.throughputPerHour} events`, "dim");
  lines.push("");

  const nameW = Math.min(20, Math.max(4, ...a.people.map((p) => clean(p.name).length)));
  add(`${"Name".padEnd(nameW)} ${"Analyses".padStart(8)} ${"Checks".padStart(6)} ${"Trusted".padStart(7)}  Status`, "cyan");
  for (const p of a.people) {
    const status = [p.working ? "working" : "", p.you ? "you" : ""].filter(Boolean).join(", ");
    add(`${clip(clean(p.name), nameW).padEnd(nameW)} ${String(p.analyses).padStart(8)} ${String(p.checks).padStart(6)} ${String(p.trusted).padStart(7)}  ${status}`, p.you ? "yellow" : undefined);
  }
  if (a.people.length === 0) add("(nobody has joined yet)", "dim");
  lines.push("");

  add("Recent", "cyan");
  for (const e of a.recent.slice(0, 8)) add(`${hhmm(e.at)}  ${clean(e.who)} ${clean(e.what)}`);
  if (a.recent.length === 0) add("(nothing yet)", "dim");
  return lines.join("\n");
}
