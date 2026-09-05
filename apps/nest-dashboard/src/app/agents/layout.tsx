import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Agents",
  description:
    "An illustrative, synthetic preview of an agent network; not a live Nanda Town registry or traffic feed.",
  alternates: { canonical: "/agents" },
};

export default function AgentsLayout({ children }: { children: React.ReactNode }) {
  return children;
}
