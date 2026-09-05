import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Experiments",
  description:
    "Frozen legacy showcase scenarios and sample metrics from the earlier Nanda Town simulator.",
  alternates: { canonical: "/experiments" },
};

export default function ExperimentsLayout({ children }: { children: React.ReactNode }) {
  return children;
}
