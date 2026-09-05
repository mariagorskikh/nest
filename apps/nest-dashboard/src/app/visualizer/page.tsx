'use client';

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import * as d3 from 'd3';
import { MaritimeCallout } from '@/components/maritime-callout';
import {
  parseTrace,
  type TraceEvent,
  type TraceFormat,
} from '@/lib/trace-adapter';

/* ------------------------------------------------------------------ */
/*  Scenarios                                                          */
/* ------------------------------------------------------------------ */

interface ScenarioMeta {
  id: string;
  name: string;
  blurb: string;
  file: string;
}

const SCENARIOS: ScenarioMeta[] = [
  {
    id: 'auction',
    name: 'Auction',
    blurb: '1 auctioneer · 19 bidders · 5 rounds',
    file: '/scenario-traces/auction.jsonl',
  },
  {
    id: 'marketplace',
    name: 'Marketplace',
    blurb: '50 buyers · 50 sellers · matched trades',
    file: '/scenario-traces/marketplace.jsonl',
  },
  {
    id: 'marketplace2',
    name: 'Marketplace II',
    blurb: 'Same matcher, alternate run · 50×50',
    file: '/scenario-traces/marketplace2.jsonl',
  },
  {
    id: 'consensus',
    name: 'Consensus',
    blurb: '1 leader · 19 followers · paxos-style rounds',
    file: '/scenario-traces/consensus.jsonl',
  },
  {
    id: 'voting',
    name: 'Voting',
    blurb: '1 proposer · 1 coordinator · 18 voters',
    file: '/scenario-traces/voting.jsonl',
  },
  {
    id: 'reputation',
    name: 'Reputation',
    blurb: '16 honest · 4 malicious · 1 observer',
    file: '/scenario-traces/reputation.jsonl',
  },
  {
    id: 'supply_chain',
    name: 'Supply chain',
    blurb: 'supplier → manufacturer → distributor → retailer',
    file: '/scenario-traces/supply_chain.jsonl',
  },
  {
    id: 'shell_marketplace',
    name: 'Shell marketplace',
    blurb: '3 buyers · 3 sellers · shell-driven brains',
    file: '/scenario-traces/shell_marketplace.jsonl',
  },
];

/* ------------------------------------------------------------------ */
/*  Role palette                                                       */
/* ------------------------------------------------------------------ */

const ROLE_COLORS: Record<string, string> = {
  auctioneer:   '#C45A3C',
  bidder:       '#5C6E5A',
  leader:       '#C45A3C',
  follower:     '#5C6E5A',
  buyer:        '#C45A3C',
  seller:       '#221F1A',
  proposer:     '#C45A3C',
  coordinator:  '#B58432',
  voter:        '#5C6E5A',
  honest:       '#5C6E5A',
  malicious:    '#C45A3C',
  observer:     '#8C8576',
  supplier:     '#B58432',
  manufacturer: '#C45A3C',
  distributor:  '#5C6E5A',
  retailer:     '#221F1A',
};

function roleOf(agent: string): string {
  return agent.replace(/-\d+$/, '');
}

function roleColor(role: string): string {
  return ROLE_COLORS[role] ?? '#6B6557';
}

/* ------------------------------------------------------------------ */
/*  Role icons — PNG illustrations where available, line-art fallback */
/* ------------------------------------------------------------------ */

const ROLE_ICON_SRC: Record<string, string> = {
  auctioneer:   '/brand/nodes/node_auctioneer_v2.png',
  buyer:        '/brand/nodes/node_buyer_v2.png',
  coordinator:  '/brand/nodes/node_coordinator_v2.png',
  distributor:  '/brand/nodes/node_distributor_v2.png',
  manufacturer: '/brand/nodes/node_manufacturer_v2.png',
  proposer:     '/brand/nodes/node_proposer_v2.png',
  retailer:     '/brand/nodes/node_retailer_v2.png',
  seller:       '/brand/nodes/node_seller_v2.png',
  supplier:     '/brand/nodes/node_supplier_v2.png',
  voter:        '/brand/nodes/node_voter_v2.png',
};

interface RoleIconProps {
  role: string;
  cx: number;
  cy: number;
  size: number;
  color: string;
  strokeWidth?: number;
}

function RoleIcon({
  role,
  cx,
  cy,
  size,
  color,
  strokeWidth = 1.4,
}: RoleIconProps) {
  const src = ROLE_ICON_SRC[role];
  if (src) {
    // PNG illustrations rendered at 1.35x the line-art size so the
    // detailed artwork reads at similar visual weight to the SVG icons.
    const renderSize = size * 1.35;
    const half = renderSize / 2;
    return (
      <image
        href={src}
        x={cx - half}
        y={cy - half}
        width={renderSize}
        height={renderSize}
        preserveAspectRatio="xMidYMid meet"
        style={{ pointerEvents: 'none' }}
      />
    );
  }

  const half = size / 2;
  const s = size / 24;
  const tx = cx - half;
  const ty = cy - half;
  const common = {
    stroke: color,
    fill: 'none' as const,
    strokeWidth: strokeWidth / s,
    strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const,
  };
  return (
    <g transform={`translate(${tx},${ty}) scale(${s})`}>
      {(() => {
        switch (role) {
          case 'auctioneer':
            return (
              <>
                <path d="M5 13 L11 7 L17 13 L11 19 Z" {...common} />
                <path d="M13 7 L20 2" {...common} />
                <path d="M3 21 L21 21" {...common} />
              </>
            );
          case 'bidder':
            return (
              <>
                <path d="M7 4 H17 V13 H7 Z" {...common} />
                <path d="M12 13 V22" {...common} />
              </>
            );
          case 'leader':
            return (
              <>
                <path
                  d="M3 8 L7 14 L12 5 L17 14 L21 8 L20 19 H4 Z"
                  {...common}
                />
                <path d="M3 21 H21" {...common} />
              </>
            );
          case 'follower':
            return (
              <>
                <circle cx={12} cy={7} r={2.8} {...common} />
                <path d="M6 21 L12 12 L18 21" {...common} />
              </>
            );
          case 'buyer':
            return (
              <>
                <path d="M5 8 L7 22 H17 L19 8 Z" {...common} />
                <path d="M9 8 V5.5 a3 3 0 0 1 6 0 V8" {...common} />
              </>
            );
          case 'seller':
            return (
              <>
                <ellipse cx={12} cy={7} rx={7} ry={2.4} {...common} />
                <path d="M5 7 V12" {...common} />
                <path d="M19 7 V12" {...common} />
                <ellipse cx={12} cy={12} rx={7} ry={2.4} {...common} />
                <path d="M5 12 V17" {...common} />
                <path d="M19 12 V17" {...common} />
                <ellipse cx={12} cy={17} rx={7} ry={2.4} {...common} />
              </>
            );
          case 'proposer':
            return (
              <>
                <path d="M4 4 H20 V15 H11 L5 21 V15 H4 Z" {...common} />
                <path d="M8 9 H16" {...common} />
                <path d="M8 12 H14" {...common} />
              </>
            );
          case 'coordinator':
            return (
              <>
                <circle cx={12} cy={12} r={3.2} {...common} />
                <path d="M12 2 V6" {...common} />
                <path d="M12 18 V22" {...common} />
                <path d="M2 12 H6" {...common} />
                <path d="M18 12 H22" {...common} />
                <path d="M5 5 L8 8" {...common} />
                <path d="M19 5 L16 8" {...common} />
                <path d="M5 19 L8 16" {...common} />
                <path d="M19 19 L16 16" {...common} />
              </>
            );
          case 'voter':
            return (
              <>
                <path d="M4 4 H20 V20 H4 Z" {...common} />
                <path d="M8 12 L11 15 L17 9" {...common} />
              </>
            );
          case 'honest':
            return (
              <>
                <path
                  d="M12 3 L20 6 V12 C20 17 16 20 12 21 C8 20 4 17 4 12 V6 Z"
                  {...common}
                />
                <path d="M8 12 L11 15 L16 9" {...common} />
              </>
            );
          case 'malicious':
            return (
              <path
                d="M13 2 L5 13 L11 13 L8 22 L19 10 L13 10 L16 2 Z"
                {...common}
              />
            );
          case 'observer':
            return (
              <>
                <path d="M2 12 Q12 4 22 12 Q12 20 2 12 Z" {...common} />
                <circle cx={12} cy={12} r={3.4} {...common} />
                <circle cx={12} cy={12} r={1} fill={color} stroke="none" />
              </>
            );
          case 'supplier':
            return (
              <>
                <path d="M4 6 H20 V20 H4 Z" {...common} />
                <path d="M4 13 H20" {...common} />
                <path d="M12 6 V20" {...common} />
              </>
            );
          case 'manufacturer':
            return (
              <>
                <circle cx={12} cy={12} r={5} {...common} />
                <circle cx={12} cy={12} r={1.6} {...common} />
                {[0, 45, 90, 135, 180, 225, 270, 315].map((deg) => {
                  const rad = (deg * Math.PI) / 180;
                  const x1 = 12 + Math.cos(rad) * 6;
                  const y1 = 12 + Math.sin(rad) * 6;
                  const x2 = 12 + Math.cos(rad) * 9;
                  const y2 = 12 + Math.sin(rad) * 9;
                  return (
                    <path
                      key={deg}
                      d={`M${x1} ${y1} L${x2} ${y2}`}
                      {...common}
                    />
                  );
                })}
              </>
            );
          case 'distributor':
            return (
              <>
                <path d="M2 9 H13 V17 H2 Z" {...common} />
                <path d="M13 12 H18 L21 15 V17 H13 Z" {...common} />
                <circle cx={6} cy={19} r={1.6} {...common} />
                <circle cx={17} cy={19} r={1.6} {...common} />
              </>
            );
          case 'retailer':
            return (
              <>
                <path d="M3 12 L12 4 L21 12 V21 H3 Z" {...common} />
                <path d="M10 21 V14 H14 V21" {...common} />
              </>
            );
          default:
            return (
              <>
                <ellipse cx={12} cy={13} rx={8.5} ry={5} {...common} />
                <path d="M5 13 L19 12" {...common} />
                <path d="M7 9 L17 17" {...common} />
                <path d="M7 17 L17 9" {...common} />
              </>
            );
        }
      })()}
    </g>
  );
}

/* ------------------------------------------------------------------ */
/*  Derived structures                                                 */
/* ------------------------------------------------------------------ */

interface Agent {
  id: string;
  role: string;
}

interface Flight {
  source: string;
  target: string;
  tStart: number;
  tEnd: number;
  kind: 'send' | 'broadcast' | 'dropped';
  msg: string;
}

interface EdgeKey {
  source: string;
  target: string;
  count: number;
}

interface Derived {
  agents: Agent[];
  agentIndex: Map<string, number>;
  flights: Flight[];
  edges: EdgeKey[];
  tMin: number;
  tMax: number;
  totalSent: number;
  totalReceived: number;
  totalDropped: number;
  totalBroadcasts: number;
}

const SEP = '__';

function edgeKey(source: string, target: string) {
  return `${source}${SEP}${target}`;
}

function derive(events: TraceEvent[]): Derived {
  const agents = new Map<string, Agent>();
  const ensureAgent = (id: string) => {
    if (!agents.has(id)) agents.set(id, { id, role: roleOf(id) });
  };

  type Pending = { from: string; to?: string; ts: number; msg: string; kind: 'send' | 'broadcast' };
  const pending = new Map<string, Pending>();
  const flights: Flight[] = [];

  let totalSent = 0;
  let totalReceived = 0;
  let totalDropped = 0;
  let totalBroadcasts = 0;

  let tMin = Infinity;
  let tMax = -Infinity;

  for (const e of events) {
    if (e.ts < tMin) tMin = e.ts;
    if (e.ts > tMax) tMax = e.ts;
    ensureAgent(e.agent);
    if (e.from) ensureAgent(e.from);
    if (e.to) ensureAgent(e.to);

    if (e.kind === 'send' && e.to && e.corr) {
      pending.set(e.corr, {
        from: e.agent,
        to: e.to,
        ts: e.ts,
        msg: e.msg ?? '',
        kind: 'send',
      });
      totalSent++;
    } else if (e.kind === 'broadcast' && e.corr) {
      pending.set(e.corr, {
        from: e.agent,
        ts: e.ts,
        msg: e.msg ?? '',
        kind: 'broadcast',
      });
      totalBroadcasts++;
    } else if (e.kind === 'receive' && e.corr && e.from) {
      const p = pending.get(e.corr);
      if (p) {
        flights.push({
          source: p.from,
          target: e.agent,
          tStart: p.ts,
          tEnd: e.ts,
          kind: p.kind,
          msg: p.msg,
        });
        if (p.kind === 'send') pending.delete(e.corr);
      } else {
        flights.push({
          source: e.from,
          target: e.agent,
          tStart: Math.max(tMin, e.ts - 1),
          tEnd: e.ts,
          kind: 'send',
          msg: e.msg ?? '',
        });
      }
      totalReceived++;
    } else if (e.kind === 'dropped' && e.from && e.corr) {
      const p = pending.get(e.corr);
      if (p && p.to) {
        flights.push({
          source: p.from,
          target: p.to,
          tStart: p.ts,
          tEnd: e.ts,
          kind: 'dropped',
          msg: p.msg,
        });
        pending.delete(e.corr);
      }
      totalDropped++;
    }
  }

  for (const [, p] of pending) {
    if (p.kind === 'send' && p.to) {
      flights.push({
        source: p.from,
        target: p.to,
        tStart: p.ts,
        tEnd: Math.max(p.ts + 1, tMax),
        kind: 'dropped',
        msg: p.msg,
      });
    }
  }

  const agentList = Array.from(agents.values());
  const agentIndex = new Map(agentList.map((a, i) => [a.id, i]));

  // Ensure each flight has a visible lifetime — synthetic traces often have
  // sub-microsecond gaps between send/receive that flash by in <1 wall frame.
  const totalSpan = isFinite(tMax - tMin) ? Math.max(tMax - tMin, 0.01) : 1;
  const minLifetime = totalSpan / 36; // ≈ 0.5 wall sec at the default 18s playback
  for (const f of flights) {
    if (f.tEnd - f.tStart < minLifetime) {
      f.tEnd = f.tStart + minLifetime;
      if (f.tEnd > tMax) tMax = f.tEnd;
    }
  }

  // Build edge counts directly without round-tripping through a single string key
  const edgeMap = new Map<string, { source: string; target: string; count: number }>();
  for (const f of flights) {
    const key = edgeKey(f.source, f.target);
    const cur = edgeMap.get(key);
    if (cur) cur.count++;
    else edgeMap.set(key, { source: f.source, target: f.target, count: 1 });
  }
  const edges: EdgeKey[] = Array.from(edgeMap.values());

  return {
    agents: agentList,
    agentIndex,
    flights,
    edges,
    tMin: isFinite(tMin) ? tMin : 0,
    tMax: isFinite(tMax) ? tMax : 1,
    totalSent,
    totalReceived,
    totalDropped,
    totalBroadcasts,
  };
}

/* ------------------------------------------------------------------ */
/*  Initial role-aware layout (used to seed the force sim)            */
/* ------------------------------------------------------------------ */

interface Pos {
  x: number;
  y: number;
}

function computeLayout(agents: Agent[], width: number, height: number): Map<string, Pos> {
  const positions = new Map<string, Pos>();
  const cx = width / 2;
  const cy = height / 2;

  const byRole = new Map<string, Agent[]>();
  for (const a of agents) {
    if (!byRole.has(a.role)) byRole.set(a.role, []);
    byRole.get(a.role)!.push(a);
  }
  for (const list of byRole.values()) {
    list.sort((a, b) => {
      const an = parseInt(a.id.split('-').pop() ?? '0', 10) || 0;
      const bn = parseInt(b.id.split('-').pop() ?? '0', 10) || 0;
      return an - bn;
    });
  }

  const roles = Array.from(byRole.keys());
  const roleCounts = roles.map((r) => byRole.get(r)!.length);
  const minDim = Math.min(width, height);

  if (roles.length >= 2 && roles.length <= 6 && roleCounts.every((c) => c === 1)) {
    const padding = minDim * 0.18;
    const usable = width - padding * 2;
    roles.forEach((r, i) => {
      const a = byRole.get(r)![0];
      const x = padding + (usable * i) / Math.max(1, roles.length - 1);
      positions.set(a.id, { x, y: cy });
    });
    return positions;
  }

  const singletonRoles = roles.filter((r) => byRole.get(r)!.length === 1);
  const largeRoles = roles.filter((r) => byRole.get(r)!.length >= 4);
  if (
    singletonRoles.length >= 1 &&
    largeRoles.length === 1 &&
    singletonRoles.length + largeRoles.length === roles.length
  ) {
    const ring = byRole.get(largeRoles[0])!;
    const ringRadius = minDim * 0.4;
    ring.forEach((a, i) => {
      const angle = (2 * Math.PI * i) / ring.length - Math.PI / 2;
      positions.set(a.id, {
        x: cx + ringRadius * Math.cos(angle),
        y: cy + ringRadius * Math.sin(angle),
      });
    });
    singletonRoles.forEach((r, i) => {
      const a = byRole.get(r)![0];
      const offsetY = (i - (singletonRoles.length - 1) / 2) * minDim * 0.08;
      positions.set(a.id, { x: cx, y: cy + offsetY });
    });
    return positions;
  }

  if (roles.length === 2 && roleCounts.every((c) => c >= 4)) {
    const [rA, rB] = roles;
    const listA = byRole.get(rA)!;
    const listB = byRole.get(rB)!;
    const colA = width * 0.22;
    const colB = width * 0.78;
    const ySpanA = height * 0.78;
    const ySpanB = height * 0.78;
    const yA0 = (height - ySpanA) / 2;
    const yB0 = (height - ySpanB) / 2;
    listA.forEach((a, i) => {
      positions.set(a.id, {
        x: colA,
        y: yA0 + (ySpanA * (i + 0.5)) / listA.length,
      });
    });
    listB.forEach((b, i) => {
      positions.set(b.id, {
        x: colB,
        y: yB0 + (ySpanB * (i + 0.5)) / listB.length,
      });
    });
    return positions;
  }

  const ringRadius = minDim * 0.34;
  const clusterRadius = (minDim * 0.32) / Math.max(2, roles.length);
  roles.forEach((r, ri) => {
    const list = byRole.get(r)!;
    const baseAngle = (2 * Math.PI * ri) / roles.length - Math.PI / 2;
    const baseX = cx + ringRadius * Math.cos(baseAngle);
    const baseY = cy + ringRadius * Math.sin(baseAngle);
    list.forEach((a, i) => {
      const inner = (2 * Math.PI * i) / Math.max(1, list.length);
      const r2 = list.length === 1 ? 0 : clusterRadius;
      positions.set(a.id, {
        x: baseX + r2 * Math.cos(inner),
        y: baseY + r2 * Math.sin(inner),
      });
    });
  });
  return positions;
}

/* ------------------------------------------------------------------ */
/*  Player — force-directed, draggable, zoomable                      */
/* ------------------------------------------------------------------ */

interface ForceNode extends d3.SimulationNodeDatum {
  id: string;
  role: string;
}

interface ForceLink extends d3.SimulationLinkDatum<ForceNode> {
  source: string | ForceNode;
  target: string | ForceNode;
  value: number;
}

interface PlayerProps {
  derived: Derived;
  simTime: number;
  setSimTime: (t: number | ((t: number) => number)) => void;
  playing: boolean;
  setPlaying: (p: boolean | ((p: boolean) => boolean)) => void;
  speed: number;
  setSpeed: (s: number) => void;
}

function Player({
  derived,
  simTime,
  setSimTime,
  playing,
  setPlaying,
  speed,
  setSpeed,
}: PlayerProps) {
  const W = 900;
  const H = 580;

  const [hover, setHover] = useState<string | null>(null);
  const [focused, setFocused] = useState<string | null>(null);
  const [view, setView] = useState({ k: 1, x: 0, y: 0 });
  const [positions, setPositions] = useState<Map<string, { x: number; y: number }>>(
    () => computeLayout(derived.agents, W, H),
  );

  const svgRef = useRef<SVGSVGElement>(null);
  const nodesRef = useRef<ForceNode[]>([]);
  const simRef = useRef<d3.Simulation<ForceNode, ForceLink> | null>(null);

  // Initialize force simulation each time the trace changes
  useEffect(() => {
    const seed = computeLayout(derived.agents, W, H);
    const nodes: ForceNode[] = derived.agents.map((a) => {
      const p = seed.get(a.id) ?? { x: W / 2, y: H / 2 };
      return { id: a.id, role: a.role, x: p.x, y: p.y, vx: 0, vy: 0 };
    });
    const links: ForceLink[] = derived.edges
      .filter((e) => e.source !== e.target && e.source && e.target)
      .map((e) => ({ source: e.source, target: e.target, value: e.count }));

    const roles = Array.from(new Set(derived.agents.map((a) => a.role)));
    const roleAngle = new Map<string, number>();
    roles.forEach((r, i) => {
      roleAngle.set(
        r,
        (2 * Math.PI * i) / Math.max(1, roles.length) - Math.PI / 2,
      );
    });
    const cx = W / 2;
    const cy = H / 2;
    const clusterR = Math.min(W, H) * 0.30;

    const n = derived.agents.length;
    const collideR = n > 60 ? 11 : n > 30 ? 15 : 22;

    const sim = d3
      .forceSimulation<ForceNode, ForceLink>(nodes)
      .force(
        'charge',
        d3.forceManyBody<ForceNode>().strength(-180).distanceMax(340),
      )
      .force(
        'link',
        d3
          .forceLink<ForceNode, ForceLink>(links)
          .id((d) => d.id)
          .distance(80)
          .strength(0.04),
      )
      .force('collide', d3.forceCollide<ForceNode>(collideR))
      .force(
        'cx',
        d3
          .forceX<ForceNode>(
            (d) => cx + Math.cos(roleAngle.get(d.role) ?? 0) * clusterR,
          )
          .strength(0.06),
      )
      .force(
        'cy',
        d3
          .forceY<ForceNode>(
            (d) => cy + Math.sin(roleAngle.get(d.role) ?? 0) * clusterR,
          )
          .strength(0.08),
      )
      .alpha(1)
      .alphaDecay(0.022)
      .on('tick', () => {
        const next = new Map<string, { x: number; y: number }>();
        for (const node of nodes) {
          next.set(node.id, { x: node.x ?? 0, y: node.y ?? 0 });
        }
        setPositions(next);
      });

    simRef.current = sim;
    nodesRef.current = nodes;

    return () => {
      sim.stop();
    };
  }, [derived]);

  // Playback animation
  const targetDuration = 18;
  const simPerWallSec =
    Math.max(derived.tMax - derived.tMin, 0.01) / targetDuration;
  const lastWall = useRef<number | null>(null);
  useEffect(() => {
    if (!playing) {
      lastWall.current = null;
      return;
    }
    let frame: number;
    const tick = (now: number) => {
      if (lastWall.current === null) lastWall.current = now;
      const dtMs = now - lastWall.current;
      lastWall.current = now;
      setSimTime((t) => {
        const next = t + (dtMs / 1000) * simPerWallSec * speed;
        if (next >= derived.tMax) {
          setPlaying(false);
          return derived.tMax;
        }
        return next;
      });
      frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [playing, speed, simPerWallSec, derived.tMax, setSimTime, setPlaying]);

  // Convert client coords to SVG world coords (post-zoom)
  const clientToSvg = useCallback((clientX: number, clientY: number) => {
    const svg = svgRef.current;
    if (!svg) return { x: 0, y: 0 };
    const rect = svg.getBoundingClientRect();
    const sx = ((clientX - rect.left) / rect.width) * W;
    const sy = ((clientY - rect.top) / rect.height) * H;
    return { x: (sx - view.x) / view.k, y: (sy - view.y) / view.k };
  }, [view]);

  // Drag a node
  const startNodeDrag = useCallback(
    (id: string, e: React.PointerEvent<SVGGElement>) => {
      if (!simRef.current) return;
      e.preventDefault();
      e.stopPropagation();
      const node = nodesRef.current.find((nn) => nn.id === id);
      if (!node) return;

      simRef.current.alphaTarget(0.3).restart();
      const start = clientToSvg(e.clientX, e.clientY);
      node.fx = start.x;
      node.fy = start.y;
      node.x = start.x;
      node.y = start.y;

      let moved = false;
      const downX = e.clientX;
      const downY = e.clientY;
      const onMove = (ev: PointerEvent) => {
        if (Math.hypot(ev.clientX - downX, ev.clientY - downY) > 3) moved = true;
        const pt = clientToSvg(ev.clientX, ev.clientY);
        node.fx = pt.x;
        node.fy = pt.y;
      };
      const onUp = () => {
        simRef.current?.alphaTarget(0);
        if (!moved) {
          node.fx = null;
          node.fy = null;
          simRef.current?.alpha(0.25).restart();
          setFocused((f) => (f === id ? null : id));
        }
        window.removeEventListener('pointermove', onMove);
        window.removeEventListener('pointerup', onUp);
      };
      window.addEventListener('pointermove', onMove);
      window.addEventListener('pointerup', onUp);
    },
    [clientToSvg],
  );

  // Pan the background
  const startBgPan = useCallback((e: React.PointerEvent<SVGSVGElement>) => {
    if ((e.target as SVGElement).closest('[data-agent]')) return;
    const startClient = { x: e.clientX, y: e.clientY };
    const startView = { x: view.x, y: view.y };
    const svg = svgRef.current!;
    const rect = svg.getBoundingClientRect();
    const onMove = (ev: PointerEvent) => {
      const dx = ((ev.clientX - startClient.x) / rect.width) * W;
      const dy = ((ev.clientY - startClient.y) / rect.height) * H;
      setView((v) => ({ ...v, x: startView.x + dx, y: startView.y + dy }));
    };
    const onUp = () => {
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
    };
    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
  }, [view.x, view.y]);

  // Mouse-wheel zoom around cursor
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    const handler = (e: WheelEvent) => {
      e.preventDefault();
      const rect = svg.getBoundingClientRect();
      const sx = ((e.clientX - rect.left) / rect.width) * W;
      const sy = ((e.clientY - rect.top) / rect.height) * H;
      const factor = e.deltaY < 0 ? 1.12 : 1 / 1.12;
      setView((v) => {
        const nextK = Math.max(0.4, Math.min(4, v.k * factor));
        const r = nextK / v.k;
        return { k: nextK, x: sx - (sx - v.x) * r, y: sy - (sy - v.y) * r };
      });
    };
    svg.addEventListener('wheel', handler, { passive: false });
    return () => svg.removeEventListener('wheel', handler);
  }, []);

  const resetView = () => setView({ k: 1, x: 0, y: 0 });

  // ------------------------- Derived state -------------------------
  interface InFlight {
    source: string;
    target: string;
    kind: 'send' | 'broadcast' | 'dropped';
    progress: number;
    msg: string;
  }
  const inFlight: InFlight[] = useMemo(() => {
    const out: InFlight[] = [];
    for (const f of derived.flights) {
      if (simTime < f.tStart) continue;
      const tail = Math.max((f.tEnd - f.tStart) * 0.04, 0.3);
      if (simTime > f.tEnd + tail) continue;
      const dur = Math.max(f.tEnd - f.tStart, 1e-6);
      let p = (simTime - f.tStart) / dur;
      if (p > 1) p = 1;
      out.push({
        source: f.source,
        target: f.target,
        kind: f.kind,
        progress: p,
        msg: f.msg,
      });
      if (out.length > 800) break;
    }
    return out;
  }, [simTime, derived.flights]);

  interface Ripple {
    id: string;
    t0: number;
    kind: 'send' | 'recv';
  }
  const ripples: Ripple[] = useMemo(() => {
    const out: Ripple[] = [];
    const lifetime = 1.4;
    for (const f of derived.flights) {
      if (simTime >= f.tStart && simTime - f.tStart < lifetime) {
        out.push({ id: f.source, t0: f.tStart, kind: 'send' });
      }
      if (
        f.kind !== 'dropped' &&
        simTime >= f.tEnd &&
        simTime - f.tEnd < lifetime
      ) {
        out.push({ id: f.target, t0: f.tEnd, kind: 'recv' });
      }
      if (out.length > 200) break;
    }
    return out;
  }, [simTime, derived.flights]);

  const activeAgents = useMemo(() => {
    const s = new Set<string>();
    for (const f of inFlight) {
      s.add(f.source);
      s.add(f.target);
    }
    return s;
  }, [inFlight]);

  const trafficWindow = (derived.tMax - derived.tMin) * 0.06;
  const recentEdges = useMemo(() => {
    const m = new Map<string, number>();
    for (const f of derived.flights) {
      if (f.tEnd < simTime - trafficWindow) continue;
      if (f.tStart > simTime) continue;
      const key = edgeKey(f.source, f.target);
      m.set(key, (m.get(key) ?? 0) + 1);
    }
    return m;
  }, [simTime, derived.flights, trafficWindow]);

  const maxRecent = Math.max(1, ...recentEdges.values());
  const maxTotal = useMemo(
    () => Math.max(1, ...derived.edges.map((e) => e.count)),
    [derived.edges],
  );

  const counters = useMemo(() => {
    let sent = 0;
    let received = 0;
    let dropped = 0;
    for (const f of derived.flights) {
      if (f.tStart <= simTime) {
        if (f.kind === 'dropped') {
          if (f.tEnd <= simTime) dropped++;
        } else {
          sent++;
          if (f.tEnd <= simTime) received++;
        }
      }
    }
    return { sent, received, dropped, inFlight: inFlight.length };
  }, [simTime, derived.flights, inFlight.length]);

  const pct =
    ((simTime - derived.tMin) / Math.max(derived.tMax - derived.tMin, 1e-6)) *
    100;

  const neighborSet = useMemo(() => {
    const target = focused ?? hover;
    if (!target) return new Set<string>();
    const s = new Set<string>();
    for (const e of derived.edges) {
      if (e.source === target) s.add(e.target);
      if (e.target === target) s.add(e.source);
    }
    return s;
  }, [hover, focused, derived.edges]);

  const agentStats = useMemo(() => {
    const m = new Map<string, { sent: number; recv: number; dropped: number }>();
    for (const a of derived.agents) {
      m.set(a.id, { sent: 0, recv: 0, dropped: 0 });
    }
    for (const f of derived.flights) {
      const s = m.get(f.source);
      const t = m.get(f.target);
      if (f.kind === 'dropped') {
        if (s) s.dropped++;
      } else {
        if (s) s.sent++;
        if (t) t.recv++;
      }
    }
    return m;
  }, [derived]);

  const fmt = (t: number) => t.toFixed(2);

  const colorOf = (kind: 'send' | 'broadcast' | 'dropped') =>
    kind === 'dropped'
      ? '#8C8576'
      : kind === 'broadcast'
      ? '#B58432'
      : '#C45A3C';

  const tooltipTarget = hover ?? focused;
  const tooltipPos = tooltipTarget ? positions.get(tooltipTarget) : undefined;
  const tooltipStats = tooltipTarget ? agentStats.get(tooltipTarget) : undefined;

  return (
    <div className="space-y-4">
      <div className="relative rounded-2xl border border-cream-400/70 bg-cream-50 overflow-hidden">
        <svg
          ref={svgRef}
          viewBox={`0 0 ${W} ${H}`}
          preserveAspectRatio="xMidYMid meet"
          className="block w-full select-none"
          style={{ aspectRatio: `${W} / ${H}`, cursor: 'grab', touchAction: 'none' }}
          onPointerDown={startBgPan}
        >
          <defs>
            <radialGradient id="bg-radial" cx="50%" cy="50%" r="75%">
              <stop offset="0%" stopColor="#F7F5EF" />
              <stop offset="100%" stopColor="#EDE7D6" />
            </radialGradient>
            <pattern id="dot-grid" width="22" height="22" patternUnits="userSpaceOnUse">
              <circle cx="1" cy="1" r="0.7" fill="#C9C1AB" opacity="0.45" />
            </pattern>
            <filter id="msg-glow" x="-60%" y="-60%" width="220%" height="220%">
              <feGaussianBlur stdDeviation="2.2" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
            <filter id="node-glow" x="-40%" y="-40%" width="180%" height="180%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          <rect width={W} height={H} fill="url(#bg-radial)" />
          <rect width={W} height={H} fill="url(#dot-grid)" />

          <g transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
            {/* Static edges — always visible, weighted by total + recent traffic */}
            {derived.edges.map((e) => {
              if (!e.source || !e.target || e.source === e.target) return null;
              const p1 = positions.get(e.source);
              const p2 = positions.get(e.target);
              if (!p1 || !p2) return null;
              const key = edgeKey(e.source, e.target);
              const recent = recentEdges.get(key) ?? 0;
              const total = e.count / maxTotal;

              const isFocusEdge =
                focused && (e.source === focused || e.target === focused);
              const isHoverEdge =
                hover && (e.source === hover || e.target === hover);

              let stroke = '#221F1A';
              let opacity = 0.05 + total * 0.12;
              let width = 0.5 + total * 1.0;

              if (recent > 0) {
                stroke = '#C45A3C';
                opacity = 0.30 + (recent / maxRecent) * 0.50;
                width = 0.9 + (recent / maxRecent) * 2.0;
              }

              if (focused) {
                if (isFocusEdge) {
                  stroke = '#C45A3C';
                  opacity = 0.75;
                  width = Math.max(width, 1.6);
                } else {
                  opacity *= 0.18;
                }
              } else if (hover) {
                if (isHoverEdge) {
                  stroke = '#C45A3C';
                  opacity = 0.6;
                  width = Math.max(width, 1.4);
                } else {
                  opacity *= 0.45;
                }
              }

              return (
                <line
                  key={key}
                  x1={p1.x}
                  y1={p1.y}
                  x2={p2.x}
                  y2={p2.y}
                  stroke={stroke}
                  strokeWidth={width}
                  strokeOpacity={opacity}
                  strokeLinecap="round"
                />
              );
            })}

            {/* Ripples — emanating pulses on each send/receive moment */}
            <g style={{ pointerEvents: 'none' }}>
              {ripples.map((r, i) => {
                const pos = positions.get(r.id);
                if (!pos) return null;
                const lifetime = 1.4;
                const age = Math.max(0, simTime - r.t0);
                const t = Math.min(1, age / lifetime);
                const radius = 8 + t * 34;
                const opacity = (1 - t) * 0.55;
                const stroke = r.kind === 'send' ? '#C45A3C' : '#5C6E5A';
                return (
                  <circle
                    key={`${r.id}-${r.t0}-${r.kind}-${i}`}
                    cx={pos.x}
                    cy={pos.y}
                    r={radius}
                    fill="none"
                    stroke={stroke}
                    strokeWidth={1.3}
                    opacity={opacity}
                  />
                );
              })}
            </g>

            {/* In-flight messages — head + glowing tail */}
            <g filter="url(#msg-glow)">
              {inFlight.map((f, i) => {
                const p1 = positions.get(f.source);
                const p2 = positions.get(f.target);
                if (!p1 || !p2) return null;
                const dx = p2.x - p1.x;
                const dy = p2.y - p1.y;
                const len = Math.hypot(dx, dy) || 1;
                const headX = p1.x + dx * f.progress;
                const headY = p1.y + dy * f.progress;
                const tailLen = Math.min(0.18, 30 / len);
                const tailP = Math.max(0, f.progress - tailLen);
                const tailX = p1.x + dx * tailP;
                const tailY = p1.y + dy * tailP;
                const stroke = colorOf(f.kind);
                const fade =
                  f.progress >= 1
                    ? Math.max(0, 1 - (f.progress - 1) * 6)
                    : 0.55 + f.progress * 0.45;
                if (f.kind === 'dropped') {
                  return (
                    <g key={i} style={{ opacity: fade }}>
                      <line
                        x1={tailX}
                        y1={tailY}
                        x2={headX}
                        y2={headY}
                        stroke={stroke}
                        strokeWidth={2}
                        strokeLinecap="round"
                        strokeDasharray="3 3"
                        opacity={0.7}
                      />
                      <circle
                        cx={headX}
                        cy={headY}
                        r={3}
                        fill="none"
                        stroke={stroke}
                        strokeWidth={1.4}
                      />
                    </g>
                  );
                }
                return (
                  <g key={i} style={{ opacity: fade }}>
                    <line
                      x1={tailX}
                      y1={tailY}
                      x2={headX}
                      y2={headY}
                      stroke={stroke}
                      strokeWidth={2.8}
                      strokeLinecap="round"
                      opacity={0.85}
                    />
                    <circle cx={headX} cy={headY} r={3.6} fill={stroke} />
                  </g>
                );
              })}
            </g>

            {/* Agent nodes — line-art icons with drag */}
            {derived.agents.map((a) => {
              const pos = positions.get(a.id);
              if (!pos) return null;
              const active = activeAgents.has(a.id);
              const isHover = hover === a.id;
              const isFocus = focused === a.id;
              const dimmed =
                (focused && focused !== a.id && !neighborSet.has(a.id)) ||
                (!focused && hover && hover !== a.id && !neighborSet.has(a.id));
              const dense = derived.agents.length > 30;
              const baseSize = dense ? 17 : 24;
              const size =
                isHover || isFocus
                  ? baseSize + 6
                  : active
                  ? baseSize + 2
                  : baseSize;
              const color = roleColor(a.role);
              const hitRadius = size * 0.85;
              const showLabel =
                derived.agents.length <= 24 || isHover || isFocus;
              return (
                <g
                  key={a.id}
                  data-agent={a.id}
                  onPointerDown={(e) => startNodeDrag(a.id, e)}
                  onMouseEnter={() => setHover(a.id)}
                  onMouseLeave={() => setHover(null)}
                  style={{
                    cursor: 'grab',
                    opacity: dimmed ? 0.18 : 1,
                    transition: 'opacity 0.2s ease',
                  }}
                >
                  {(active || isHover || isFocus) && (
                    <circle
                      cx={pos.x}
                      cy={pos.y}
                      r={size * 0.7}
                      fill={color}
                      fillOpacity={isFocus ? 0.18 : isHover ? 0.14 : 0.08}
                      stroke={color}
                      strokeOpacity={isFocus ? 0.55 : 0.4}
                      strokeWidth={isFocus ? 1.4 : 1}
                    />
                  )}
                  <g filter={active ? 'url(#node-glow)' : undefined}>
                    <RoleIcon
                      role={a.role}
                      cx={pos.x}
                      cy={pos.y}
                      size={size}
                      color={color}
                      strokeWidth={isHover || isFocus ? 1.8 : 1.4}
                    />
                  </g>
                  <circle
                    cx={pos.x}
                    cy={pos.y}
                    r={hitRadius}
                    fill="transparent"
                  />
                  {showLabel && (
                    <text
                      x={pos.x}
                      y={pos.y + size * 0.7 + 11}
                      textAnchor="middle"
                      fontSize={9}
                      fontWeight={500}
                      fill="#353129"
                      style={{ pointerEvents: 'none' }}
                    >
                      {a.id}
                    </text>
                  )}
                </g>
              );
            })}
          </g>
        </svg>

        {/* Tooltip */}
        {tooltipTarget && tooltipPos && tooltipStats && (
          <div
            className="pointer-events-none absolute z-10 rounded-lg border border-cream-400/80 bg-cream-50/95 shadow-md px-3 py-2 text-[11px] text-ink-700"
            style={{
              left: `calc(${((tooltipPos.x * view.k + view.x) / W) * 100}% + 14px)`,
              top: `calc(${((tooltipPos.y * view.k + view.y) / H) * 100}% - 10px)`,
              transform: 'translateY(-100%)',
            }}
          >
            <div className="font-mono text-[10px] uppercase tracking-[0.18em] text-ink-400">
              {tooltipTarget}
            </div>
            <div className="mt-1 flex gap-3 font-mono tabular-nums">
              <span>
                <span className="text-rust">●</span> {tooltipStats.sent} sent
              </span>
              <span>
                <span className="text-sage">●</span> {tooltipStats.recv} recv
              </span>
              {tooltipStats.dropped > 0 && (
                <span>
                  <span className="text-ink-300">●</span>{' '}
                  {tooltipStats.dropped} dropped
                </span>
              )}
            </div>
          </div>
        )}

        {/* Sim time overlay */}
        <div className="absolute left-4 top-4 flex items-center gap-2 rounded-full border border-cream-400/70 bg-cream-50/90 px-3 py-1.5 font-mono text-[10px] uppercase tracking-[0.22em] text-ink-500">
          <span
            className={`inline-block h-1.5 w-1.5 rounded-full ${
              playing ? 'bg-rust animate-pulse' : 'bg-ink-300'
            }`}
          />
          <span>t = {fmt(simTime)}</span>
          <span className="text-ink-300">/ {fmt(derived.tMax)}</span>
        </div>

        {/* Live counters */}
        <div className="absolute right-4 top-4 flex gap-4 rounded-2xl border border-cream-400/70 bg-cream-50/90 px-4 py-2 font-mono text-[10px] uppercase tracking-[0.18em] text-ink-500">
          <span className="flex items-center gap-1.5">
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-rust" />
            <span className="text-ink-300">sent</span>
            <span className="text-ink-900 tabular-nums">{counters.sent}</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-sage" />
            <span className="text-ink-300">recv</span>
            <span className="text-ink-900 tabular-nums">{counters.received}</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-amber" />
            <span className="text-ink-300">flight</span>
            <span className="text-rust tabular-nums">{counters.inFlight}</span>
          </span>
          {derived.totalDropped > 0 && (
            <span className="flex items-center gap-1.5">
              <span className="inline-block h-1.5 w-1.5 rounded-full bg-ink-300" />
              <span className="text-ink-300">drop</span>
              <span className="text-ink-900 tabular-nums">{counters.dropped}</span>
            </span>
          )}
        </div>

        {/* View controls */}
        <div className="absolute left-4 bottom-4 flex items-center gap-1 rounded-full border border-cream-400/70 bg-cream-50/90 px-1 py-1 font-mono text-[10px] uppercase tracking-[0.18em] text-ink-500">
          <button
            type="button"
            onClick={() =>
              setView((v) => {
                const k = Math.min(4, v.k * 1.2);
                const r = k / v.k;
                return {
                  k,
                  x: W / 2 - (W / 2 - v.x) * r,
                  y: H / 2 - (H / 2 - v.y) * r,
                };
              })
            }
            className="h-6 w-6 rounded-full hover:bg-cream-200"
            aria-label="Zoom in"
          >
            +
          </button>
          <button
            type="button"
            onClick={() =>
              setView((v) => {
                const k = Math.max(0.4, v.k / 1.2);
                const r = k / v.k;
                return {
                  k,
                  x: W / 2 - (W / 2 - v.x) * r,
                  y: H / 2 - (H / 2 - v.y) * r,
                };
              })
            }
            className="h-6 w-6 rounded-full hover:bg-cream-200"
            aria-label="Zoom out"
          >
            −
          </button>
          <button
            type="button"
            onClick={resetView}
            className="h-6 px-2 rounded-full hover:bg-cream-200"
            aria-label="Reset view"
          >
            fit
          </button>
        </div>

        {/* Focus banner */}
        {focused && (
          <div className="absolute bottom-4 right-4 flex items-center gap-2 rounded-full border border-rust/40 bg-rust-bg/90 px-3 py-1.5 font-mono text-[10px] uppercase tracking-[0.18em] text-rust">
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-rust" />
            <span>focus · {focused}</span>
            <button
              type="button"
              onClick={() => setFocused(null)}
              className="ml-1 text-rust hover:text-ink-900"
            >
              ✕
            </button>
          </div>
        )}
      </div>

      {/* Hint */}
      <div className="font-mono text-[10px] uppercase tracking-[0.18em] text-ink-300 px-1">
        drag nodes to rearrange · scroll to zoom · drag canvas to pan · click an
        agent to focus
      </div>

      {/* Sparkline + transport controls */}
      <div className="rounded-2xl border border-cream-400/70 bg-cream-50 px-5 py-4 space-y-3">
        <Sparkline
          derived={derived}
          simTime={simTime}
          onSeek={(t) => setSimTime(t)}
        />

        <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
          <button
            onClick={() => {
              if (simTime >= derived.tMax) setSimTime(derived.tMin);
              setPlaying((p) => !p);
            }}
            className="inline-flex h-9 w-20 items-center justify-center rounded-full bg-ink-900 text-cream-50 text-[0.85rem] font-medium hover:bg-ink-700 transition-colors"
          >
            {playing ? 'Pause' : simTime >= derived.tMax ? 'Replay' : 'Play'}
          </button>

          <input
            type="range"
            min={0}
            max={1000}
            value={Math.round(pct * 10)}
            onChange={(ev) => {
              const v = Number(ev.target.value) / 1000;
              setSimTime(derived.tMin + v * (derived.tMax - derived.tMin));
            }}
            className="flex-1 accent-rust"
          />

          <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.22em] text-ink-400">
            <span>speed</span>
            {[0.25, 0.5, 1, 2, 4].map((s) => (
              <button
                key={s}
                onClick={() => setSpeed(s)}
                className={`px-2 py-1 rounded ${
                  speed === s
                    ? 'bg-ink-900 text-cream-50'
                    : 'text-ink-500 hover:bg-cream-200'
                }`}
              >
                {s}×
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Sparkline of message density + scrub cursor                       */
/* ------------------------------------------------------------------ */

interface SparklineProps {
  derived: Derived;
  simTime: number;
  onSeek: (t: number) => void;
}

function Sparkline({ derived, simTime, onSeek }: SparklineProps) {
  const W = 800;
  const H = 36;
  const bins = 80;

  const { hist, max } = useMemo(() => {
    const arr = new Array(bins).fill(0) as number[];
    const span = Math.max(derived.tMax - derived.tMin, 1e-6);
    for (const f of derived.flights) {
      const i = Math.min(
        bins - 1,
        Math.max(0, Math.floor(((f.tStart - derived.tMin) / span) * bins)),
      );
      arr[i] += 1;
    }
    return { hist: arr, max: Math.max(1, ...arr) };
  }, [derived]);

  const span = derived.tMax - derived.tMin || 1;
  const cursorX = ((simTime - derived.tMin) / span) * W;

  const svgRef = useRef<SVGSVGElement>(null);
  const seekFromEvent = (clientX: number) => {
    const target = svgRef.current;
    if (!target) return;
    const rect = target.getBoundingClientRect();
    const f = Math.max(0, Math.min(1, (clientX - rect.left) / rect.width));
    onSeek(derived.tMin + f * span);
  };

  return (
    <svg
      ref={svgRef}
      viewBox={`0 0 ${W} ${H}`}
      preserveAspectRatio="none"
      className="block w-full h-9 cursor-pointer"
      onClick={(e) => seekFromEvent(e.clientX)}
    >
      <line x1={0} y1={H - 0.5} x2={W} y2={H - 0.5} stroke="#C9C1AB" strokeWidth={1} />
      {hist.map((v, i) => {
        const x = (i / bins) * W;
        const w = W / bins - 1;
        const h = (v / max) * (H - 6);
        const colored = (i / bins) * span + derived.tMin <= simTime;
        return (
          <rect
            key={i}
            x={x}
            y={H - h}
            width={Math.max(1, w)}
            height={h}
            rx={1}
            fill={colored ? '#C45A3C' : '#C9C1AB'}
            opacity={colored ? 0.75 : 0.55}
          />
        );
      })}
      <line x1={cursorX} y1={0} x2={cursorX} y2={H} stroke="#221F1A" strokeWidth={1.2} />
      <circle cx={cursorX} cy={4} r={2.4} fill="#221F1A" />
    </svg>
  );
}

/* ------------------------------------------------------------------ */
/*  Legend                                                             */
/* ------------------------------------------------------------------ */

function Legend({ agents }: { agents: Agent[] }) {
  const roles = useMemo(() => {
    const m = new Map<string, number>();
    for (const a of agents) m.set(a.role, (m.get(a.role) ?? 0) + 1);
    return Array.from(m.entries());
  }, [agents]);

  return (
    <div className="rounded-2xl border border-cream-400/70 bg-cream-50 p-5">
      <h3 className="font-mono text-[10px] uppercase tracking-[0.22em] text-rust mb-4">
        Roles
      </h3>
      <ul className="space-y-2">
        {roles.map(([role, count]) => {
          const color = roleColor(role);
          return (
            <li
              key={role}
              className="flex items-center justify-between text-[0.88rem]"
            >
              <span className="flex items-center gap-2.5">
                <svg width={22} height={22} viewBox="0 0 22 22">
                  <RoleIcon role={role} cx={11} cy={11} size={20} color={color} />
                </svg>
                <span className="capitalize text-ink-700">{role}</span>
              </span>
              <span className="font-mono text-[11px] tabular-nums text-ink-400">
                {count}
              </span>
            </li>
          );
        })}
      </ul>
      <div className="mt-5 pt-4 border-t border-cream-400/60 space-y-2 text-[0.78rem] text-ink-500">
        <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-rust mb-2">
          Messages
        </p>
        <div className="flex items-center gap-2">
          <svg width={20} height={8} viewBox="0 0 20 8">
            <line x1="2" y1="4" x2="18" y2="4" stroke="#C45A3C" strokeWidth={2.2} strokeLinecap="round" />
            <circle cx="18" cy="4" r="1.6" fill="#C45A3C" />
          </svg>
          <span>send</span>
        </div>
        <div className="flex items-center gap-2">
          <svg width={20} height={8} viewBox="0 0 20 8">
            <line x1="2" y1="4" x2="18" y2="4" stroke="#B58432" strokeWidth={2.2} strokeLinecap="round" />
            <circle cx="18" cy="4" r="1.6" fill="#B58432" />
          </svg>
          <span>broadcast</span>
        </div>
        <div className="flex items-center gap-2">
          <svg width={20} height={8} viewBox="0 0 20 8">
            <line x1="2" y1="4" x2="18" y2="4" stroke="#8C8576" strokeWidth={2.2} strokeLinecap="round" strokeDasharray="2 2" />
          </svg>
          <span>dropped</span>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  MessageStream — windowed live feed centered on simTime            */
/* ------------------------------------------------------------------ */

interface MessageStreamProps {
  derived: Derived;
  simTime: number;
}

function MessageStream({ derived, simTime }: MessageStreamProps) {
  const recent = useMemo(() => {
    const span = Math.max(derived.tMax - derived.tMin, 1e-6);
    const lookback = span * 0.08;
    const cut = simTime - lookback;
    const result: Flight[] = [];
    for (let i = derived.flights.length - 1; i >= 0; i--) {
      const f = derived.flights[i];
      if (f.tStart > simTime) continue;
      if (f.tStart < cut) break;
      result.push(f);
      if (result.length >= 80) break;
    }
    return result;
  }, [derived, simTime]);

  return (
    <div className="rounded-2xl border border-cream-400/70 bg-cream-50">
      <div className="border-b border-cream-400/70 px-5 py-3 flex items-center justify-between">
        <h3 className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-400">
          Live stream
        </h3>
        <span className="font-mono text-[10px] tabular-nums text-ink-300">
          {recent.length}
        </span>
      </div>
      <ul className="max-h-[420px] overflow-y-auto divide-y divide-cream-400/40 text-[0.78rem]">
        {recent.length === 0 && (
          <li className="px-4 py-4 font-mono text-[10px] uppercase tracking-[0.18em] text-ink-300">
            quiet…
          </li>
        )}
        {recent.map((f, i) => (
          <li
            key={i}
            className="flex items-center gap-2 px-4 py-2 hover:bg-cream-200/50 transition-colors"
          >
            <span className="font-mono text-[10px] text-ink-300 tabular-nums w-12 shrink-0 text-right">
              {f.tStart.toFixed(1)}
            </span>
            <span
              className="inline-block h-1.5 w-1.5 rounded-full shrink-0"
              style={{
                backgroundColor:
                  f.kind === 'dropped'
                    ? '#8C8576'
                    : f.kind === 'broadcast'
                    ? '#B58432'
                    : '#C45A3C',
              }}
            />
            <span className="font-mono text-[10px] text-ink-500 truncate">
              {f.source} → {f.target}
            </span>
            <span className="ml-auto truncate font-mono text-[10px] text-ink-400 max-w-[110px]">
              {f.msg}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Page                                                               */
/* ------------------------------------------------------------------ */

export default function VisualizerPage() {
  const [scenarioId, setScenarioId] = useState<string>('auction');
  const [events, setEvents] = useState<TraceEvent[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [customName, setCustomName] = useState<string | null>(null);
  const [traceFormat, setTraceFormat] = useState<TraceFormat | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Playback state — lifted so MessageStream can subscribe too
  const [simTime, setSimTime] = useState(0);
  const [playing, setPlaying] = useState(true);
  const [speed, setSpeed] = useState(1);

  const loadScenario = useCallback(async (id: string) => {
    const s = SCENARIOS.find((sc) => sc.id === id);
    if (!s) return;
    setLoading(true);
    setError(null);
    setCustomName(null);
    setScenarioId(id);
    try {
      const res = await fetch(s.file);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const text = await res.text();
      const parsed = parseTrace(text);
      if (parsed.events.length === 0) throw new Error('Trace has no visualizable message events');
      setEvents(parsed.events);
      setSimTime(parsed.events[0].ts);
      setPlaying(true);
      setTraceFormat(parsed.format);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load trace');
      setEvents(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void Promise.resolve().then(() => loadScenario('auction'));
  }, [loadScenario]);

  const handleFile = useCallback((file: File) => {
    setLoading(true);
    setError(null);
    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        const text = ev.target?.result as string;
        const parsed = parseTrace(text);
        if (parsed.events.length === 0) {
          throw new Error(
            parsed.format === 'town-event'
              ? 'No lifecycle or message-delivery events in this TownEvent file'
              : 'No valid events in file',
          );
        }
        setEvents(parsed.events);
        setSimTime(parsed.events[0].ts);
        setPlaying(true);
        setTraceFormat(parsed.format);
        setCustomName(file.name);
        setScenarioId('custom');
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Bad file');
      } finally {
        setLoading(false);
      }
    };
    reader.readAsText(file);
  }, []);

  const derived = useMemo(
    () => (events ? derive(events) : null),
    [events],
  );

  return (
    <div className="bg-cream-100">
      <section className="paper-texture border-b border-cream-400/70">
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 pt-20 pb-14">
          <div className="flex items-center gap-3 mb-10 animate-fade-in">
            <span className="inline-flex h-1.5 w-1.5 rounded-full bg-rust" />
            <span className="eyebrow">Visualizer · live playback</span>
          </div>

          <div className="grid gap-12 lg:grid-cols-[1.4fr_1fr] lg:items-end">
            <div className="animate-fade-in stagger-1 flex items-start gap-5">
              <h1 className="font-display text-[clamp(2.6rem,6vw,5rem)] leading-[1.02] tracking-tight text-ink-900">
                Watch a<br />
                <span className="italic text-rust">simulation</span><br />
                actually move.
              </h1>
            </div>
            <p className="animate-fade-in stagger-2 text-[1.1rem] leading-[1.6] text-ink-500 max-w-md">
              Every pulse is a recorded message from a Nanda Town trace. Drag
              agents around, scrub the timeline, or drop in a{' '}
              <span className="font-mono text-rust">events.jsonl</span> from your own{' '}
              <span className="font-mono text-rust">nandatown run</span>.
            </p>
          </div>
        </div>
      </section>

      <div className="mx-auto max-w-[1240px] px-6 sm:px-10 py-10">
        <div className="animate-fade-in stagger-1">
          <div className="flex items-center justify-between gap-4 mb-4">
            <h2 className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-400">
              Bundled legacy showcase traces
            </h2>
            <button
              onClick={() => fileInputRef.current?.click()}
              className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-400 hover:text-rust transition-colors"
            >
              + load custom .jsonl
            </button>
            <input
              ref={fileInputRef}
              type="file"
              accept=".jsonl,.json,.ndjson"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) handleFile(f);
              }}
            />
          </div>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {SCENARIOS.map((s) => {
              const active = scenarioId === s.id;
              return (
                <button
                  key={s.id}
                  onClick={() => loadScenario(s.id)}
                  className={`group relative overflow-hidden rounded-xl border px-4 py-3 text-left transition-all ${
                    active
                      ? 'border-rust bg-rust-bg/60'
                      : 'border-cream-400/70 bg-cream-50 hover:border-rust/40'
                  }`}
                >
                  {active && (
                    <span className="absolute left-0 top-0 h-full w-[3px] bg-rust" />
                  )}
                  <div className="text-[0.92rem] font-medium text-ink-900">
                    {s.name}
                  </div>
                  <div
                    className={`mt-1 text-[0.74rem] leading-snug ${
                      active ? 'text-ink-600' : 'text-ink-400'
                    }`}
                  >
                    {s.blurb}
                  </div>
                </button>
              );
            })}
            {customName && (
              <div className="rounded-xl border border-rust bg-rust-bg/40 px-4 py-3">
                <div className="text-[0.92rem] font-medium text-rust">
                  Custom
                </div>
                <div className="mt-1 text-[0.74rem] leading-snug text-ink-500 truncate">
                  {customName} · {traceFormat === 'town-event' ? 'current TownEvent' : traceFormat}
                </div>
              </div>
            )}
          </div>
        </div>

        {loading && (
          <p className="mt-8 font-mono text-[11px] uppercase tracking-[0.22em] text-ink-400">
            Loading trace…
          </p>
        )}
        {error && (
          <p className="mt-8 font-mono text-[11px] uppercase tracking-[0.22em] text-rust">
            {error}
          </p>
        )}

        {derived && (
          <div className="mt-8 animate-fade-in stagger-2">
            <div className="mb-8 grid grid-cols-2 md:grid-cols-5 gap-6 border-t border-rust/40 pt-8">
              {[
                { label: 'Agents', value: derived.agents.length, accent: '#C45A3C' },
                { label: 'Messages', value: derived.flights.length, accent: '#B58432' },
                {
                  label: 'Sent',
                  value: derived.totalSent + derived.totalBroadcasts,
                  accent: '#5C6E5A',
                },
                { label: 'Dropped', value: derived.totalDropped, accent: '#8C8576' },
                {
                  label: 'Duration',
                  value: (derived.tMax - derived.tMin).toFixed(1),
                  suffix: 's',
                  accent: '#221F1A',
                },
              ].map((stat) => (
                <div key={stat.label}>
                  <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-400 flex items-center gap-1.5">
                    <span
                      className="inline-block h-1 w-1 rounded-full"
                      style={{ backgroundColor: stat.accent }}
                    />
                    {stat.label}
                  </p>
                  <p className="mt-2 font-display text-[2rem] leading-none text-ink-900 tabular-nums">
                    {stat.value}
                    {'suffix' in stat && stat.suffix && (
                      <span className="ml-1 text-[1rem] text-rust">
                        {stat.suffix}
                      </span>
                    )}
                  </p>
                </div>
              ))}
            </div>

            <div className="grid gap-6 lg:grid-cols-[1fr_300px]">
              <Player
                key={`${scenarioId}:${customName ?? ''}`}
                derived={derived}
                simTime={simTime}
                setSimTime={setSimTime}
                playing={playing}
                setPlaying={setPlaying}
                speed={speed}
                setSpeed={setSpeed}
              />
              <div className="space-y-6">
                <Legend agents={derived.agents} />
                <MessageStream derived={derived} simTime={simTime} />
              </div>
            </div>

            <MaritimeCallout
              className="mt-6"
              title="Want to run this with agents in the cloud?"
            />
          </div>
        )}
      </div>
    </div>
  );
}
