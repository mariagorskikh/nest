import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Visualizer",
  description:
    "Load current Nanda Town events.jsonl evidence or a labeled legacy showcase trace and inspect message flow in the browser.",
  alternates: { canonical: "/visualizer" },
};

export default function VisualizerLayout({ children }: { children: React.ReactNode }) {
  return children;
}
