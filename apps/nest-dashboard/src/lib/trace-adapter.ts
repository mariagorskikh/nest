export type TraceKind =
  | "start"
  | "stop"
  | "send"
  | "receive"
  | "broadcast"
  | "dropped";

export interface TraceEvent {
  ts: number;
  agent: string;
  kind: TraceKind;
  from?: string;
  to?: string;
  msg?: string;
  size?: number;
  corr?: string;
}

export type TraceFormat =
  | "town-event"
  | "legacy-trace"
  | "mixed"
  | "unknown";

export interface ParsedTrace {
  events: TraceEvent[];
  format: TraceFormat;
  invalidLines: number;
}

interface TownEvent {
  event_id: string;
  run_id: string;
  at: number;
  observer: string;
  kind: string;
  subject: string;
  detail: Record<string, unknown>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function nonemptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isTownEvent(value: unknown): value is TownEvent {
  if (!isRecord(value)) return false;
  return (
    nonemptyString(value.event_id) &&
    nonemptyString(value.run_id) &&
    typeof value.at === "number" &&
    Number.isFinite(value.at) &&
    nonemptyString(value.observer) &&
    nonemptyString(value.kind) &&
    nonemptyString(value.subject) &&
    isRecord(value.detail)
  );
}

const TRACE_KINDS = new Set<TraceKind>([
  "start",
  "stop",
  "send",
  "receive",
  "broadcast",
  "dropped",
]);

function asLegacyTrace(value: unknown): TraceEvent | null {
  if (!isRecord(value)) return null;
  if (
    typeof value.ts !== "number" ||
    !Number.isFinite(value.ts) ||
    !nonemptyString(value.agent) ||
    !nonemptyString(value.kind) ||
    !TRACE_KINDS.has(value.kind as TraceKind)
  ) {
    return null;
  }

  const event: TraceEvent = {
    ts: value.ts,
    agent: value.agent,
    kind: value.kind as TraceKind,
  };
  for (const field of ["from", "to", "msg", "corr"] as const) {
    const fieldValue = value[field];
    if (typeof fieldValue === "string") event[field] = fieldValue;
    else if (fieldValue !== undefined) return null;
  }
  if (value.size !== undefined) {
    if (typeof value.size !== "number" || !Number.isFinite(value.size)) {
      return null;
    }
    event.size = value.size;
  }
  return event;
}

function detailString(event: TownEvent, field: string): string | null {
  const value = event.detail[field];
  return nonemptyString(value) ? value : null;
}

function adaptTownEvents(events: TownEvent[]): TraceEvent[] {
  const adapted: TraceEvent[] = [];
  const pending = new Map<
    string,
    { from: string; to: string; msg: string }
  >();

  for (const event of events) {
    // Message IDs are scoped to a run; concatenated traces can reuse them.
    const correlation = JSON.stringify([event.run_id, event.subject]);
    if (event.kind === "participant_joined") {
      adapted.push({ ts: event.at, agent: event.subject, kind: "start" });
      continue;
    }

    if (event.kind === "message_sent" || event.kind === "message_accepted") {
      const from =
        event.kind === "message_sent"
          ? event.observer
          : detailString(event, "sender");
      const to = detailString(event, "to");
      if (!from || !to) continue;
      const msg = detailString(event, "kind") ?? event.kind;
      pending.set(correlation, { from, to, msg });
      adapted.push({
        ts: event.at,
        agent: from,
        kind: "send",
        to,
        msg,
        corr: correlation,
      });
      continue;
    }

    if (event.kind === "message_delivered" || event.kind === "message_claimed") {
      const original = pending.get(correlation);
      const to =
        event.kind === "message_delivered"
          ? detailString(event, "to")
          : detailString(event, "claimant");
      if (!original || !to) continue;
      adapted.push({
        ts: event.at,
        agent: to,
        kind: "receive",
        from: original.from,
        msg: detailString(event, "kind") ?? original.msg,
        corr: correlation,
      });
      continue;
    }

    if (event.kind === "message_dropped") {
      const original = pending.get(correlation);
      const to = detailString(event, "to") ?? original?.to;
      if (!original || !to) continue;
      adapted.push({
        ts: event.at,
        agent: original.from,
        kind: "dropped",
        from: original.from,
        to,
        msg: detailString(event, "kind") ?? original.msg,
        corr: correlation,
      });
    }
  }

  return adapted;
}

function normalizeTimeline(events: TraceEvent[]): TraceEvent[] {
  const normalized = [...events].sort((a, b) => a.ts - b.ts);
  if (normalized.length < 2) return normalized;

  const minTs = normalized[0].ts;
  const maxTs = normalized[normalized.length - 1].ts;
  if (maxTs - minTs >= 1e-6) return normalized;

  return normalized.map((event, index) => ({
    ...event,
    ts: (index / Math.max(1, normalized.length - 1)) * 10,
  }));
}

/**
 * Parse current Town evidence events or the dashboard's frozen legacy samples.
 * Current records are adapted only when they contain an explicit lifecycle or
 * message-delivery fact; unrelated evidence is not invented as traffic.
 */
export function parseTrace(text: string): ParsedTrace {
  const current: TownEvent[] = [];
  const legacy: TraceEvent[] = [];
  let invalidLines = 0;

  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    try {
      const value: unknown = JSON.parse(line);
      if (isTownEvent(value)) current.push(value);
      else {
        const event = asLegacyTrace(value);
        if (event) legacy.push(event);
        else invalidLines += 1;
      }
    } catch {
      invalidLines += 1;
    }
  }

  const format: TraceFormat =
    current.length > 0 && legacy.length > 0
      ? "mixed"
      : current.length > 0
        ? "town-event"
        : legacy.length > 0
          ? "legacy-trace"
          : "unknown";

  return {
    events: normalizeTimeline([...adaptTownEvents(current), ...legacy]),
    format,
    invalidLines,
  };
}
