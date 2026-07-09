/**
 * /hackathon/layers/[layer] — submission list for a single layer.
 *
 * Server component owns the dataset + 404 handling; the
 * client-side `LayerSubmissions` sub-component owns sort UI.
 */
import Link from "next/link";
import { notFound } from "next/navigation";
import { loadDataset, submissionsForLayer } from "@/lib/hackathon";
import { LayerSubmissions } from "./layer-submissions";
export const revalidate = 300;
export async function generateStaticParams() {
  // Pre-render every known layer at build time. Other slugs fall
  // through to the dynamic path and 404 on first request.
  const data = await loadDataset();
  return data.layers.map((layer) => ({ layer: layer.key }));
}
export default async function LayerPage({
  params,
}: {
  params: Promise<{ layer: string }>;
}) {
  const { layer } = await params;
  const data = await loadDataset();
  const meta = data.layers.find((l) => l.key === layer);
  if (!meta) {
    notFound();
  }
  const subs = submissionsForLayer(data, meta.key);
  return (
    <div className="bg-cream-100">
      <section className="paper-texture border-b border-cream-400/70">
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 pt-16 pb-12">
          <div className="flex items-center gap-3 mb-8 animate-fade-in">
            <Link
              href="/hackathon/layers"
              className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-300 hover:text-ink-900"
            >
              ← Layers
            </Link>
          </div>
          <div className="grid gap-10 lg:grid-cols-[1.4fr_1fr] lg:items-end">
            <div>
              <p className="eyebrow">Layer · {meta.label.toLowerCase()}</p>
              <h1 className="mt-4 font-display animate-fade-in stagger-1 text-[clamp(2.2rem,5.2vw,3.8rem)] leading-[1.04] tracking-tight text-ink-900">
                {meta.label}
              </h1>
              <p className="mt-4 text-[1.05rem] leading-[1.6] text-ink-500 max-w-xl">
                {meta.blurb}
              </p>
            </div>
            <dl className="grid grid-cols-2 gap-6 font-mono text-[10px] uppercase tracking-[0.18em] text-ink-300">
              <div>
                <dt>Submissions</dt>
                <dd className="mt-2 font-display text-[1.6rem] leading-none text-ink-900 tabular-nums">
                  {subs.length}
                </dd>
              </div>
              <div>
                <dt>Top score</dt>
                <dd className="mt-2 font-display text-[1.6rem] leading-none text-ink-900 tabular-nums">
                  {meta.top_score !== null
                    ? meta.top_score.toFixed(1)
                    : subs.length === 0
                      ? "—"
                      : "unscored"}
                </dd>
              </div>
            </dl>
          </div>
        </div>
      </section>
      <section>
        <div className="mx-auto max-w-[1240px] px-6 sm:px-10 py-12">
          <LayerSubmissions submissions={subs} layerLabel={meta.label} />
        </div>
      </section>
    </div>
  );
}
