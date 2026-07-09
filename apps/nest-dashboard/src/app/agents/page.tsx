"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  geoNaturalEarth1,
  geoPath,
  type GeoPermissibleObjects,
  type GeoProjection,
} from "d3-geo";
import { feature } from "topojson-client";
import type {
  Topology,
  GeometryCollection,
  GeometryObject,
} from "topojson-specification";
import type { Feature, FeatureCollection } from "geojson";
import {
  clusters,
  clusterLinks,
  jitterAgents,
  totalAgents,
  type AgentCluster,
  type MessageLink,
} from "@/lib/agent-network";
import { ImagePlaceholder } from "@/components/image-placeholder";

const WIDTH = 1100;
const HEIGHT = 560;

/* ---------------------------------------------------------------- */
/*  World map hook                                                   */
/* ---------------------------------------------------------------- */

interface WorldData {
  countries: FeatureCollection;
  projection: GeoProjection;
  path: (g: GeoPermissibleObjects) => string;
}

function useWorldMap(): WorldData | null {
  const [data, setData] = useState<WorldData | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch("/world-110m.json")
      .then((r) => r.json() as Promise<Topology>)
      .then((topo) => {
        if (cancelled) return;
        const countries = feature(
          topo,
          topo.objects.countries as GeometryCollection<GeometryObject>,
        ) as unknown as FeatureCollection;

        const projection = geoNaturalEarth1()
          .scale(195)
          .translate([WIDTH / 2, HEIGHT / 2 + 10]);

        const path = geoPath(projection) as unknown as (
          g: GeoPermissibleObjects,
        ) => string;

        setData({ countries, projection, path });
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  return data;
}

/* ---------------------------------------------------------------- */
/*  Animated message lines                                           */
/* ---------------------------------------------------------------- */

interface ActiveMessage {
  id: number;
  link: MessageLink;
  bornAt: number;
}

function useMessageStream(intervalMs = 650, lifetimeMs = 2400) {
  const [messages, setMessages] = useState<ActiveMessage[]>([]);
  const idRef = useRef(0);

  useEffect(() => {
    const tick = setInterval(() => {
      const now = performance.now();
      idRef.current += 1;
      const link =
        clusterLinks[Math.floor(Math.random() * clusterLinks.length)];
      setMessages((prev) =>
        [
          ...prev.filter((m) => now - m.bornAt < lifetimeMs),
          { id: idRef.current, link, bornAt: now },
        ].slice(-18),
      );
    }, intervalMs);

    const sweep = setInterval(() => {
      const now = performance.now();
      setMessages((prev) => prev.filter((m) => now - m.bornAt < lifetimeMs));
    }, 1000);

    return () => {
      clearInterval(tick);
      clearInterval(sweep);
    };
  }, [intervalMs, lifetimeMs]);

  return messages;
}

/* ---------------------------------------------------------------- */
/*  Stat                                                              */
/* ---------------------------------------------------------------- */

function Stat({
  label,
  value,
  hint,
}: {
  label: string;
  value: string;
  hint?: string;
}) {
  return (
    <div>
      <span className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-300">
        {label}
      </span>
      <p className="mt-3 font-display text-[2.2rem] leading-none text-ink-900 tabular-nums">
        {value}
      </p>
      {hint && (
        <span className="mt-2 block text-[0.85rem] text-ink-400">{hint}</span>
      )}
    </div>
  );
}

/* ---------------------------------------------------------------- */
/*  Map                                                              */
/* ---------------------------------------------------------------- */

function AgentMap({
  world,
  hovered,
  setHovered,
}: {
  world: WorldData | null;
  hovered: string | null;
  setHovered: (city: string | null) => void;
}) {
  const projectedClusters = useMemo(() => {
    if (!world) return [];
    return clusters
      .map((c) => {
        const p = world.projection(c.coords);
        return p ? { ...c, x: p[0], y: p[1] } : null;
      })
      .filter((c): c is AgentCluster & { x: number; y: number } => c !== null);
  }, [world]);

  const projectedAgents = useMemo(() => {
    if (!world) return [];
    return clusters
      .flatMap((c) => {
        const agents = jitterAgents(c);
        return agents.map((a) => {
          const p = world.projection(a.coords);
          return p ? { ...a, x: p[0], y: p[1] } : null;
        });
      })
      .filter(
        (a): a is {
          id: string;
          cluster: string;
          x: number;
          y: number;
          coords: [number, number];
        } => a !== null,
      );
  }, [world]);

  const messages = useMessageStream();

  // Clock state — updated each animation frame so the message-tip
  // animation reads a stable, pure value during render.
  const [now, setNow] = useState(0);
  useEffect(() => {
    let raf = 0;
    const loop = () => {
      setNow(performance.now());
      raf = requestAnimationFrame(loop);
    };
    raf = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(raf);
  }, []);

  const projectedMessages = useMemo(() => {
    if (!world) return [];
    return messages
      .map((m) => {
        const a = world.projection(m.link.from);
        const b = world.projection(m.link.to);
        if (!a || !b) return null;
        const age = now - m.bornAt;
        return {
          id: m.id,
          fromCity: m.link.fromCity,
          toCity: m.link.toCity,
          x1: a[0],
          y1: a[1],
          x2: b[0],
          y2: b[1],
          age,
        };
      })
      .filter((m): m is NonNullable<typeof m> => m !== null);
  }, [messages, world, now]);

  return (
    <div className="rounded-2xl border border-cream-400/70 bg-cream-50 p-5">
      <svg
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        className="block w-full h-auto"
        style={{ overflow: "visible" }}
      >
        <defs>
          <filter id="agent-glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="1.5" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <radialGradient id="msg-head" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#C45A3C" stopOpacity="0.95" />
            <stop offset="60%" stopColor="#C45A3C" stopOpacity="0.5" />
            <stop offset="100%" stopColor="#C45A3C" stopOpacity="0" />
          </radialGradient>
        </defs>

        {/* Faint horizontal bands */}
        {Array.from({ length: 5 }, (_, i) => (
          <line
            key={`hb-${i}`}
            x1={0}
            x2={WIDTH}
            y1={(HEIGHT / 5) * (i + 1) - 30}
            y2={(HEIGHT / 5) * (i + 1) - 30}
            stroke="#E8E4D6"
            strokeWidth={1}
          />
        ))}

        {/* Countries */}
        {world &&
          world.countries.features.map((f: Feature, i: number) => (
            <path
              key={`country-${i}`}
              d={world.path(f) || ""}
              fill="#EDE8DA"
              stroke="#DDD7C5"
              strokeWidth={0.6}
            />
          ))}

        {!world && (
          <text
            x={WIDTH / 2}
            y={HEIGHT / 2}
            textAnchor="middle"
            fontSize={13}
            fill="#8C8576"
            fontFamily="var(--font-mono)"
          >
            Loading map…
          </text>
        )}

        {/* Message edges */}
        {projectedMessages.map((m) => {
          const drawDur = 1200;
          const t = Math.min(1, m.age / drawDur);
          const ease = 1 - Math.pow(1 - t, 3);
          const hx = m.x1 + (m.x2 - m.x1) * ease;
          const hy = m.y1 + (m.y2 - m.y1) * ease;
          const fade =
            m.age <= drawDur
              ? 1
              : Math.max(0, 1 - (m.age - drawDur) / 1200);

          return (
            <g key={`msg-${m.id}`} opacity={fade}>
              <line
                x1={m.x1}
                y1={m.y1}
                x2={hx}
                y2={hy}
                stroke="#C45A3C"
                strokeWidth={0.9}
                strokeOpacity={0.5}
                strokeLinecap="round"
              />
              <circle cx={hx} cy={hy} r={3} fill="url(#msg-head)" />
            </g>
          );
        })}

        {/* Agent dots */}
        {projectedAgents.map((a) => {
          const isHot = hovered === a.cluster;
          return (
            <circle
              key={a.id}
              cx={a.x}
              cy={a.y}
              r={isHot ? 2.4 : 1.6}
              fill={isHot ? "#C45A3C" : "#221F1A"}
              opacity={isHot ? 1 : 0.55}
              style={{ transition: "all 0.25s ease" }}
            />
          );
        })}

        {/* Clusters */}
        {projectedClusters.map((c) => {
          const isHot = hovered === c.city;
          return (
            <g
              key={c.city}
              onMouseEnter={() => setHovered(c.city)}
              onMouseLeave={() => setHovered(null)}
              style={{ cursor: "pointer" }}
            >
              <circle
                cx={c.x}
                cy={c.y}
                r={isHot ? 16 : 10}
                fill="#C45A3C"
                opacity={isHot ? 0.16 : 0.08}
                style={{ transition: "all 0.25s ease" }}
              />
              <circle
                cx={c.x}
                cy={c.y}
                r={isHot ? 4.5 : 3.5}
                fill="#C45A3C"
                filter={isHot ? "url(#agent-glow)" : undefined}
                style={{ transition: "all 0.25s ease" }}
              />
              <g style={{ pointerEvents: "none" }}>
                <text
                  x={c.x + 8}
                  y={c.y - 6}
                  fontSize={11}
                  fontFamily="var(--font-sans)"
                  fontWeight={500}
                  fill="#141312"
                  opacity={isHot ? 1 : 0.85}
                >
                  {c.city}
                </text>
                <text
                  x={c.x + 8}
                  y={c.y + 6}
                  fontSize={9}
                  fontFamily="var(--font-mono)"
                  fill="#6B6557"
                  opacity={isHot ? 1 : 0.6}
                  letterSpacing={0.4}
                >
                  {c.region} · {c.agents}
                </text>
              </g>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

/* ---------------------------------------------------------------- */
/*  Cluster list                                                      */
/* ---------------------------------------------------------------- */

function ClusterList({
  hovered,
  setHovered,
}: {
  hovered: string | null;
  setHovered: (city: string | null) => void;
}) {
  const sorted = useMemo(
    () => [...clusters].sort((a, b) => b.agents - a.agents),
    [],
  );
  return (
    <div className="rounded-2xl border border-cream-400/70 bg-cream-50 overflow-hidden">
      <div className="border-b border-cream-400/70 px-5 py-4">
        <h3 className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-400">
          Clusters &middot; sorted by population
        </h3>
      </div>
      <ul className="divide-y divide-cream-400/50">
        {sorted.map((c) => {
          const isHot = hovered === c.city;
          return (
            <li
              key={c.city}
              onMouseEnter={() => setHovered(c.city)}
              onMouseLeave={() => setHovered(null)}
              className={`flex items-center gap-4 px-5 py-3.5 transition-colors cursor-default ${
                isHot ? "bg-cream-200" : ""
              }`}
            >
              <span
                className="h-1.5 w-1.5 rounded-full"
                style={{
                  background: isHot ? "#C45A3C" : "#221F1A",
                  opacity: isHot ? 1 : 0.65,
                }}
              />
              <div className="flex-1 min-w-0">
                <p className="text-[0.95rem] text-ink-900 leading-tight truncate">
                  {c.city}
                  {c.affiliation && (
                    <span className="ml-2 text-[0.8rem] text-ink-300 font-normal">
                      {c.affiliation}
                    </span>
                  )}
                </p>
                <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-ink-300 mt-1">
                  {c.region}
                </p>
              </div>
              <span className="font-display text-[1.15rem] tabular-nums text-ink-700">
                {c.agents}
              </span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

/* ---------------------------------------------------------------- */
/*  Page                                                             */
/* ---------------------------------------------------------------- */

export default function AgentsPage() {
  const world = useWorldMap();
  const [hovered, setHovered] = useState<string | null>(null);

  const [, setTick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setTick((t) => (t + 1) % 1_000_000), 60);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="bg-cream-100">
      {/* Header */}
      <section className="paper-texture border-b border-cream-400/70">
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 pt-20 pb-16">
          <div className="grid gap-12 lg:grid-cols-[1.4fr_1fr] lg:items-start">
            <h1 className="font-display animate-fade-in stagger-1 text-[clamp(2.6rem,6vw,5rem)] leading-[1.02] tracking-tight text-ink-900">
              The agent
              <br />
              network,
              <br />
              <span className="italic text-ink-700">in motion.</span>
            </h1>

            <p className="animate-fade-in stagger-2 text-[1.1rem] leading-[1.6] text-ink-500 lg:pt-6 max-w-md">
              A live view of agents running on Nanda Town across
              the world. Each dot is an agent; each line is a message exchanged
              between clusters. The data is synthetic &mdash; built on a seeded
              layout &mdash; and updates continuously.
            </p>
          </div>
        </div>
      </section>

      {/* Stats */}
      <section className="border-b border-cream-400/70">
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 py-12 grid grid-cols-2 md:grid-cols-4 gap-10">
          <Stat label="Agents" value={String(totalAgents)} hint="across all clusters" />
          <Stat label="Clusters" value={String(clusters.length)} hint="major regions" />
          <Stat label="Msgs/min" value="~92" hint="rolling 1-min average" />
          <Stat label="Uptime" value="99.94%" hint="last 30 days" />
        </div>
      </section>

      {/* Map + sidebar */}
      <section>
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 py-14 grid gap-8 lg:grid-cols-[1fr_340px]">
          <AgentMap world={world} hovered={hovered} setHovered={setHovered} />
          <ClusterList hovered={hovered} setHovered={setHovered} />
        </div>
      </section>

      {/* Quote / image band */}
      <section className="border-t border-cream-400/70 bg-cream-50">
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 py-24 grid gap-12 lg:grid-cols-[1.4fr_1fr] lg:items-center">
          <div>
            <p className="eyebrow">From the field</p>
            <p className="mt-6 font-display text-[clamp(1.6rem,2.8vw,2.4rem)] leading-[1.2] italic text-ink-700">
              &ldquo;You can&rsquo;t understand what agents are doing by reading
              code. You have to <span className="not-italic text-ink-900">watch</span> the
              network, then ask why the lines drew themselves that way.&rdquo;
            </p>
            <p className="mt-6 font-mono text-[10px] uppercase tracking-[0.22em] text-ink-300">
              Nanda Town design note &middot; cluster topology
            </p>
          </div>
          <ImagePlaceholder
            id="C"
            ratio="4/5"
            src="/illustrations/img_03_constellations.png"
            alt="Aerial-view scatter of warm rust-orange dots on cream paper, joined by faint orange threads forming organic constellations."
            sizes="(min-width: 1024px) 40vw, 100vw"
            prompt="Abstract aerial-view composition of warm rust-orange dots scattered across cream paper, connected by faint orange threads forming organic constellations. Hand-drawn, ink-and-wash feel. Soft cream background #F0EDE4, accent rust #C45A3C, hints of warm brown. No text, no characters, no logos."
            caption="Section divider — agent constellations"
          />
        </div>
      </section>
    </div>
  );
}
