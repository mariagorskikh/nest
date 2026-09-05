"""The visualizer: one self-contained HTML file that replays a run.

Agents sit on a town map, messages animate between them as the timeline
plays, the event log scrolls in step, and the stage verdicts stay in
view. No network, no external assets: the whole run travels in the file.
"""

from __future__ import annotations

import json
from html import escape
from typing import Any

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>NANDA Town run __RUN_ID__</title>
<style>
  :root { --bg: #101418; --panel: #1a2027; --line: #2c3540;
          --text: #e6edf3; --dim: #8b98a5; --good: #3fb950;
          --bad: #f85149; --warn: #d29922; --accent: #58a6ff; }
  * { box-sizing: border-box; margin: 0; }
  body { background: var(--bg); color: var(--text);
         font: 14px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace;
         padding: 16px; }
  h1 { font-size: 16px; margin-bottom: 4px; }
  .meta { color: var(--dim); margin-bottom: 12px; }
  .grid { display: grid; grid-template-columns: 1fr 380px; gap: 12px; }
  @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
  .panel { background: var(--panel); border: 1px solid var(--line);
           border-radius: 8px; padding: 12px; }
  svg { width: 100%; height: 420px; display: block; }
  .agent circle { fill: #263040; stroke: var(--accent); stroke-width: 1.5; }
  .agent text { fill: var(--text); font-size: 11px; text-anchor: middle; }
  .agent .role { fill: var(--dim); font-size: 9px; }
  .edge { stroke: var(--line); stroke-width: 1; }
  .pulse { fill: var(--accent); }
  .pulse.dropped { fill: var(--bad); }
  .controls { display: flex; gap: 8px; align-items: center;
              margin-top: 8px; }
  input[type=range] { flex: 1; }
  button { background: #263040; color: var(--text); border: 1px solid
           var(--line); border-radius: 6px; padding: 4px 14px;
           cursor: pointer; }
  button:hover { border-color: var(--accent); }
  #log { height: 300px; overflow-y: auto; font-size: 12px; }
  #log div { padding: 1px 4px; border-left: 2px solid transparent; }
  #log div.current { background: #223; border-left-color: var(--accent); }
  #log .k { color: var(--accent); }
  #log .o { color: var(--dim); }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  td { padding: 2px 6px; border-top: 1px solid var(--line); }
  .passed { color: var(--good); }
  .failed { color: var(--bad); }
  .not_enough_evidence { color: var(--warn); }
  .not_tested { color: var(--dim); }
  .error { color: var(--bad); }
  .verdict { font-size: 15px; font-weight: bold; margin: 6px 0; }
  .scope { color: var(--dim); font-size: 11px; margin-top: 10px; }
</style>
</head>
<body>
<h1>NANDA Town System Fitness Report: <span id="title"></span></h1>
<div class="meta" id="meta"></div>
<div class="grid">
  <div class="panel">
    <svg id="map" viewBox="0 0 640 420"></svg>
    <div class="controls">
      <button id="play">Play</button>
      <input type="range" id="scrub" min="0" value="0">
      <span id="clock" style="color:var(--dim)"></span>
    </div>
  </div>
  <div class="panel">
    <div class="verdict" id="verdict"></div>
    <table id="stages"></table>
    <div class="scope">This result applies only to the named agents,
    releases, scenario, failure, evaluator, and time window. One run is
    one scoped observation, not a certificate.</div>
  </div>
</div>
<div class="panel" style="margin-top:12px">
  <div style="color:var(--dim);margin-bottom:6px">Event log</div>
  <div id="log"></div>
</div>
<script id="data" type="application/json">__DATA__</script>
<script>
const data = JSON.parse(document.getElementById('data').textContent);
const agents = data.participants;
const events = data.events;
document.getElementById('title').textContent = data.title;
document.getElementById('meta').textContent = data.meta;
const v = document.getElementById('verdict');
v.textContent = 'Verdict: ' + data.result.verdict.toUpperCase();
v.className = 'verdict ' +
  (data.result.verdict === 'passed' ? 'passed' : 'failed');
const stages = document.getElementById('stages');
const statuses = new Set(['passed', 'failed', 'not_enough_evidence',
                          'not_tested', 'error']);
for (const s of data.result.stages) {
  const tr = document.createElement('tr');
  const name = document.createElement('td');
  name.textContent = s.name;
  const status = document.createElement('td');
  status.textContent = s.status.replaceAll('_', ' ');
  if (statuses.has(s.status)) status.className = s.status;
  tr.append(name, status);
  stages.appendChild(tr);
}
const svg = document.getElementById('map');
const cx = 320, cy = 200, R = 150;
const pos = Object.create(null);
agents.forEach((a, i) => {
  const ang = (2 * Math.PI * i) / agents.length - Math.PI / 2;
  pos[a.name] = [cx + R * Math.cos(ang), cy + R * Math.sin(ang)];
});
const NS = 'http://www.w3.org/2000/svg';
function el(tag, attrs) {
  const e = document.createElementNS(NS, tag);
  for (const k in attrs) e.setAttribute(k, attrs[k]);
  return e;
}
for (const a of agents) {
  const [x, y] = pos[a.name];
  const g = el('g', {class: 'agent'});
  g.appendChild(el('circle', {cx: x, cy: y, r: 26}));
  const t1 = el('text', {x: x, y: y - 2}); t1.textContent = a.name;
  const t2 = el('text', {x: x, y: y + 11, class: 'role'});
  t2.textContent = a.role;
  g.appendChild(t1); g.appendChild(t2);
  svg.appendChild(g);
}
const log = document.getElementById('log');
events.forEach((e, i) => {
  const d = document.createElement('div');
  const observer = document.createElement('span');
  observer.className = 'o';
  observer.textContent = '[' + e.observer + ']';
  const kind = document.createElement('span');
  kind.className = 'k';
  kind.textContent = e.kind;
  d.append('t=' + e.at.toFixed(2) + ' ', observer, ' ', kind, ' ',
           e.subject, ' ',
           Object.keys(e.detail).length ? JSON.stringify(e.detail) : '');
  d.id = 'ev' + i;
  log.appendChild(d);
});
const scrub = document.getElementById('scrub');
scrub.max = Math.max(0, events.length - 1);
scrub.disabled = events.length === 0;
document.getElementById('play').disabled = events.length === 0;
let playing = null;
function pulse(from, to, dropped) {
  if (!pos[from] || !pos[to]) return;
  const [x1, y1] = pos[from], [x2, y2] = pos[to];
  const dot = el('circle',
                 {r: 6, class: 'pulse' + (dropped ? ' dropped' : '')});
  svg.appendChild(dot);
  const t0 = performance.now();
  function step(t) {
    const p = Math.min((t - t0) / 500, 1);
    dot.setAttribute('cx', x1 + (x2 - x1) * p);
    dot.setAttribute('cy', y1 + (y2 - y1) * p);
    if (p < 1) requestAnimationFrame(step); else dot.remove();
  }
  requestAnimationFrame(step);
}
function show(i, animate) {
  const e = events[i];
  document.querySelectorAll('#log .current')
    .forEach(x => x.classList.remove('current'));
  const row = document.getElementById('ev' + i);
  row.classList.add('current');
  row.scrollIntoView({block: 'nearest'});
  document.getElementById('clock').textContent =
    't=' + e.at.toFixed(2) + '  ' + (i + 1) + '/' + events.length;
  if (animate && e.detail && e.detail.to) {
    const from = e.kind === 'message_delivered' ? e.detail.from : e.observer;
    pulse(e.observer === 'town' ? (e.detail.from || e.observer)
          : e.observer, e.detail.to, e.kind === 'message_dropped');
  }
}
scrub.addEventListener('input', () => show(+scrub.value, true));
document.getElementById('play').addEventListener('click', function () {
  if (playing) { clearInterval(playing); playing = null;
                 this.textContent = 'Play'; return; }
  this.textContent = 'Pause';
  if (+scrub.value >= events.length - 1) scrub.value = 0;
  playing = setInterval(() => {
    if (+scrub.value >= events.length - 1) {
      clearInterval(playing); playing = null;
      document.getElementById('play').textContent = 'Play'; return;
    }
    scrub.value = +scrub.value + 1;
    show(+scrub.value, true);
  }, 350);
});
if (events.length) show(0, false);
</script>
</body>
</html>
"""


def render_visualizer(bundle: dict[str, Any]) -> str:
    run = bundle["run"]
    profile = bundle["profile"]
    result = bundle["result"]
    if bundle.get("mode") == "lab":
        meta = (f"Lab scenario {profile.name}, seed"
                f" {run.config.get('seed')}, deterministic replay of"
                f" {len(bundle['events'])} events")
    elif bundle.get("mode") == "path":
        meta = (f"Path profile {profile.ref}, capability {profile.capability},"
                f" {len(bundle['events'])} events")
    else:
        meta = (f"Track profile {profile.name}, fault {profile.fault},"
                f" {len(bundle['events'])} events")
    data = {
        "title": run.run_id,
        "meta": meta,
        "participants": [{"name": p["name"], "role": p.get("role", "?")}
                         for p in run.participants],
        "events": [e.model_dump() for e in bundle["events"]],
        "result": result.model_dump(),
    }
    payload = (json.dumps(data).replace("<", "\\u003c")
               .replace(">", "\\u003e").replace("&", "\\u0026"))
    return (TEMPLATE
            .replace("__RUN_ID__", escape(run.run_id))
            .replace("__DATA__", payload))


def write_visualizer(bundle: dict[str, Any], out_path: str) -> str:
    with open(out_path, "w") as f:
        f.write(render_visualizer(bundle))
    return out_path
