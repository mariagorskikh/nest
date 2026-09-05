import { expect, test } from "vitest";
import { parseTrace } from "@/lib/trace-adapter";

test("adapts current TownEvent delivery facts without changing their attribution", () => {
  const currentEvents = [
    '{"event_id":"ev-5","run_id":"sim-example","at":0.0,"observer":"town","kind":"participant_joined","subject":"seller-a","detail":{"role":"seller"}}',
    '{"event_id":"ev-11","run_id":"sim-example","at":0.0,"observer":"town","kind":"participant_joined","subject":"buyer-1","detail":{"role":"buyer"}}',
    '{"event_id":"ev-14","run_id":"sim-example","at":0.5,"observer":"buyer-1","kind":"message_sent","subject":"m-1","detail":{"to":"seller-a","kind":"quote_request","conversation":"c-1","body":{"sku":"widget"}}}',
    '{"event_id":"ev-16","run_id":"sim-example","at":0.6,"observer":"town","kind":"message_delivered","subject":"m-1","detail":{"to":"seller-a","kind":"quote_request"}}',
  ].join("\n");

  const parsed = parseTrace(currentEvents);

  expect(parsed.format).toBe("town-event");
  expect(parsed.invalidLines).toBe(0);
  expect(parsed.events).toEqual([
    { ts: 0, agent: "seller-a", kind: "start" },
    { ts: 0, agent: "buyer-1", kind: "start" },
    {
      ts: 0.5,
      agent: "buyer-1",
      kind: "send",
      to: "seller-a",
      msg: "quote_request",
      corr: "m-1",
    },
    {
      ts: 0.6,
      agent: "seller-a",
      kind: "receive",
      from: "buyer-1",
      msg: "quote_request",
      corr: "m-1",
    },
  ]);
});

test("adapts current Track accepted, claimed, and dropped message facts", () => {
  const currentEvents = [
    '{"event_id":"ev-1","run_id":"track-example","at":10,"observer":"town","kind":"message_accepted","subject":"work-1","detail":{"sender":"buyer","to":"seller","kind":"quote_request","content_fingerprint":"sha256:x"}}',
    '{"event_id":"ev-2","run_id":"track-example","at":11,"observer":"town","kind":"message_claimed","subject":"work-1","detail":{"claimant":"seller","attempt":1,"fence":"fence-1"}}',
    '{"event_id":"ev-3","run_id":"track-example","at":12,"observer":"town","kind":"message_accepted","subject":"work-2","detail":{"sender":"seller","to":"buyer","kind":"quote_response","content_fingerprint":"sha256:y"}}',
    '{"event_id":"ev-4","run_id":"track-example","at":13,"observer":"town","kind":"message_dropped","subject":"work-2","detail":{"to":"buyer","kind":"quote_response","fault":"drop"}}',
  ].join("\n");

  const parsed = parseTrace(currentEvents);

  expect(parsed.format).toBe("town-event");
  expect(parsed.events).toEqual([
    { ts: 10, agent: "buyer", kind: "send", to: "seller", msg: "quote_request", corr: "work-1" },
    { ts: 11, agent: "seller", kind: "receive", from: "buyer", msg: "quote_request", corr: "work-1" },
    { ts: 12, agent: "seller", kind: "send", to: "buyer", msg: "quote_response", corr: "work-2" },
    { ts: 13, agent: "seller", kind: "dropped", from: "seller", to: "buyer", msg: "quote_response", corr: "work-2" },
  ]);
});

test("keeps the bundled legacy trace format supported", () => {
  const parsed = parseTrace([
    '{"agent":"buyer-0","kind":"send","ts":1,"to":"seller-0","msg":"quote","corr":"m-1"}',
    '{"agent":"seller-0","kind":"receive","ts":2,"from":"buyer-0","msg":"quote","corr":"m-1"}',
  ].join("\n"));

  expect(parsed.format).toBe("legacy-trace");
  expect(parsed.events).toEqual([
    { agent: "buyer-0", kind: "send", ts: 1, to: "seller-0", msg: "quote", corr: "m-1" },
    { agent: "seller-0", kind: "receive", ts: 2, from: "buyer-0", msg: "quote", corr: "m-1" },
  ]);
});

test("rejects malformed records instead of inventing missing event attribution", () => {
  const parsed = parseTrace([
    "not json",
    '{"event_id":"ev-1","run_id":"r","at":"now","observer":"town","kind":"message_sent","subject":"m","detail":{}}',
    '{"event_id":"ev-2","run_id":"r","at":1,"observer":"town","kind":"message_sent","subject":"m","detail":[]}',
    '{"agent":"buyer","kind":"unknown","ts":0}',
  ].join("\n"));

  expect(parsed).toEqual({ events: [], format: "unknown", invalidLines: 4 });
});
