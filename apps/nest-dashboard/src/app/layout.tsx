import type { Metadata } from "next";
import "./globals.css";
import { Navbar } from "@/components/navbar";
import { Footer } from "@/components/footer";
import { HackathonBanner } from "@/components/hackathon-banner";

const SITE_URL = "https://nandatown.projectnanda.org";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: {
    default: "Nanda Town — by Project NANDA",
    template: "%s — Nanda Town",
  },
  description:
    "Nanda Town is a local-first lab for declared agent workflows and protocol simulations with stage-separated evidence. By Project NANDA.",
  keywords: [
    "AI agents",
    "agent integration testing",
    "agent evidence",
    "Project NANDA",
    "Nanda Town",
    "local-first agent lab",
    "agentic commerce",
    "AI agent testing",
  ],
  applicationName: "Nanda Town",
  authors: [{ name: "Project NANDA", url: "https://projectnanda.org" }],
  creator: "Project NANDA",
  openGraph: {
    type: "website",
    url: SITE_URL,
    siteName: "Nanda Town",
    title: "Nanda Town — by Project NANDA",
    description:
      "A local-first lab for declared agent workflows and protocol simulations with stage-separated evidence.",
    images: [
      {
        url: "/brand/nanda-logo-color.png",
        width: 500,
        height: 500,
        alt: "Nanda Town — a sandbox for AI agents, by Project NANDA",
      },
    ],
    locale: "en_US",
  },
  twitter: {
    card: "summary",
    title: "Nanda Town — by Project NANDA",
    description:
      "A local-first integration lab for exact agent paths and reproducible evidence.",
    images: ["/brand/nanda-logo-color.png"],
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      "max-image-preview": "large",
      "max-snippet": -1,
    },
  },
  icons: {
    icon: [
      { url: "/favicon.ico", sizes: "any" },
      { url: "/favicon-32.png", sizes: "32x32", type: "image/png" },
      { url: "/favicon-16.png", sizes: "16x16", type: "image/png" },
    ],
    apple: "/apple-touch-icon.png",
  },
};

const organizationJsonLd = {
  "@context": "https://schema.org",
  "@type": "Organization",
  name: "Project NANDA",
  url: "https://projectnanda.org",
  logo: `${SITE_URL}/brand/nanda-logo-color.png`,
  sameAs: ["https://github.com/projnanda"],
};

const webSiteJsonLd = {
  "@context": "https://schema.org",
  "@type": "WebSite",
  name: "Nanda Town",
  url: SITE_URL,
  description:
    "A local-first lab for declared agent workflows and protocol simulations with stage-separated evidence.",
  publisher: { "@type": "Organization", name: "Project NANDA" },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full bg-cream-100 text-ink-900">
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(organizationJsonLd) }}
        />
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(webSiteJsonLd) }}
        />
        <HackathonBanner />
        <div className="flex min-h-screen flex-col md:flex-row">
          <Navbar />
          <div className="flex min-w-0 flex-1 flex-col">
            <main className="flex-1">{children}</main>
            <Footer />
          </div>
        </div>
      </body>
    </html>
  );
}
