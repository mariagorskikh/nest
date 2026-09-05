import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Docs",
  description:
    "Install Nanda Town, exercise an exact Lab, Track, or Path workflow, and verify stage-separated local evidence.",
  alternates: { canonical: "/docs" },
};

const softwareJsonLd = {
  "@context": "https://schema.org",
  "@type": "SoftwareApplication",
  name: "Nanda Town",
  applicationCategory: "DeveloperApplication",
  operatingSystem: "macOS, Linux, Windows",
  description:
    "Local-first integration lab for exact agent, service, and protocol paths with reproducible evidence.",
  url: "https://nandatown.projectnanda.org/docs",
  installUrl: "https://github.com/projnanda/nandatown#quick-start",
  offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
  publisher: { "@type": "Organization", name: "Project NANDA" },
};

export default function DocsLayout({ children }: { children: React.ReactNode }) {
  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(softwareJsonLd) }}
      />
      {children}
    </>
  );
}
