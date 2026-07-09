import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Nanda Summit + NandaHack Demos @ MIT — Nanda Town",
  description:
    "Nanda Summit and NandaHack demos at MIT Media Lab with HCLTech, Saturday July 11th, 2026.",
};

const LUMA_URL = "https://lu.ma/6q9q00sm";
const SHOWCASE_FORM =
  "https://docs.google.com/forms/d/e/1FAIpQLSftTT0StXcNIA708ropgFtbClyNxv-kcm0w8EvxSNPxPGJAHg/viewform";
const SOVEREIGN_DOC =
  "https://docs.google.com/document/d/1CPTeGieguR_Jbq69YnWqMMM4m9tm0POekTbUbQn82ag/edit?tab=t.0#heading=h.z6ne0og04bp5";
const DATAFACTS_POST =
  "https://www.linkedin.com/feed/update/urn:li:activity:7476851966506131456/";

const MORNING: [string, string][] = [
  ["9:30 am", "Opening Keynote by HCLTech and MIT Media Lab: Trustworthy Infrastructure for AI Agents (Jeff Turnham, Grace Davin, Jie Hui, Pradyumna Chari, Ramesh Raskar)"],
  ["10:00 - 10:30 am", "Sovereign AI agents: Boston and India (Santiago Garces, CIO City of Boston and Ramesh Raskar, Prof. MIT)"],
  ["10:30 - 11:00 am", "From Alexa to Agentic Commerce, panel discussion (Rohit Prasad, former head of Alexa)"],
  ["11:00 - 11:30 am", "Venture Landscape in Agentic Web (Host: John Werner. Panelists: Marc Weber*, John Harthorne*, Habib Haddad*)"],
  ["11:30 - 12:00 pm", "Agentic Systems (Abhishek Mehta, Tresata; Abhi Yadav, iCustomer; Rahul Todkar; Karan Bharadwaj; Maria Gorskikh, Maritime)"],
  ["12:00 - 12:30 pm", "From Agents to Agentic Societies (Ayush Chopra, Pradyumna Chari)"],
  ["12:30 - 1:00 pm", "Enterprise Agentic Web (Rob Lincourt, Dell)"],
];

const AFTERNOON: [string, string][] = [
  ["2:00 - 2:15 pm", "Opening Keynote"],
  ["2:15 - 2:30 pm", "NandaTown Introduction and Tutorials"],
  ["2:30 - 4:30 pm", "Demos from top 10 teams"],
  ["4:30 - 5:00 pm", "Demo Awards and Summary"],
];

function Ext({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" className="font-medium text-rust transition-colors hover:text-ink-900">
      {children}
    </a>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mt-14">
      <h2 className="font-display text-[1.7rem] leading-tight text-ink-900">{title}</h2>
      <div className="mt-5 space-y-4 text-[1.02rem] leading-[1.7] text-ink-500">{children}</div>
    </section>
  );
}

export default function SummitPage() {
  return (
    <div className="mx-auto max-w-3xl px-6 pb-24 pt-12 lg:px-10">
      <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-300">
        Saturday, July 11th, 2026 · MIT Media Lab · with HCLTech
      </p>
      <h1 className="mt-4 font-display text-[2.6rem] leading-[1.08] text-ink-900">
        Nanda Summit + NandaHack Demos @ MIT
      </h1>
      <p className="mt-5 text-[1.05rem] leading-[1.7] text-ink-500">
        Join us for the Nanda Summit at MIT Media Lab.
      </p>
      <ul className="mt-3 list-disc space-y-2 pl-5 text-[1.02rem] leading-[1.7] text-ink-500">
        <li>The morning session includes top industry and research leaders, along with working group discussions.</li>
        <li>The afternoon includes tutorials, hackathon awards and interaction with our judges.</li>
      </ul>
      <div className="mt-7 flex flex-wrap gap-3">
        <a href={LUMA_URL} target="_blank" rel="noopener noreferrer" className="rounded-full bg-ink-900 px-6 py-3 text-[0.92rem] font-medium text-cream-100 transition-colors hover:bg-ink-700">
          Register on Luma
        </a>
        <a href="https://nandahack.media.mit.edu" target="_blank" rel="noopener noreferrer" className="rounded-full border border-cream-400 px-6 py-3 text-[0.92rem] font-medium text-ink-900 transition-colors hover:bg-cream-200">
          NandaHack details
        </a>
      </div>

      <Section title="Important note for hackathon participants">
        <ul className="list-disc space-y-3 pl-5">
          <li>There will be <strong className="text-ink-900">no coding / building</strong> at the in person event; only demos and interaction with other builders and judges. You should build and submit your demo by Friday July 10th at Noon ET. <strong className="text-ink-900">ALL submissions are due on Friday July 10th.</strong></li>
          <li>The hackathon participants are <strong className="text-ink-900">not required to attend</strong> this event, and your <strong className="text-ink-900">score will not be impacted by not attending</strong>. You can still win without being at the event.</li>
          <li>You do NOT need to register on this Luma if you are participating virtually.</li>
          <li>If you are participating for the hackathon judging sessions in person, each team member must register on this Luma <strong className="text-ink-900">individually</strong> as an acceptance to this event grants individual entry, not team entry.</li>
        </ul>
        <p>
          Research and Startup <strong className="text-ink-900">Innovation Showcase</strong>: apply to present your demo, research or startup innovation via <Ext href={SHOWCASE_FORM}>this form</Ext>.
        </p>
      </Section>

      <Section title="Summit Sessions (9:30 am - 1 pm)">
        <ul className="space-y-3">
          {MORNING.map(([time, what]) => (
            <li key={time} className="flex gap-4">
              <span className="w-32 shrink-0 font-mono text-[0.8rem] uppercase tracking-wide text-ink-300">{time}</span>
              <span>{what}</span>
            </li>
          ))}
        </ul>
        <p>
          The Sovereign AI agents session has a companion doc: <Ext href={SOVEREIGN_DOC}>AI Agents for MA working groups</Ext> (working groups meet at 1 pm, sign up at that link).
        </p>
        <p>
          1 pm: Showcase of your innovations (<Ext href={SHOWCASE_FORM}>apply here</Ext>) and Research Council Meetings (by invitation for MIT research council members).
        </p>
      </Section>

      <Section title="NandaHack (2 pm - 5 pm)">
        <p>
          Details at <Ext href="https://nandahack.media.mit.edu">nandahack.media.mit.edu</Ext>.
        </p>
        <p>
          The NandaHack, by MIT Media Lab and HCLTech invites builders to create and demo real agentic applications inside NandaTown, a sandbox for the Internet of AI Agents. Teams will explore how autonomous agents can discover each other, coordinate tasks, exchange information, and work together across an open ecosystem. The hackathon will feature tutorials, demos from top teams, judges from AI and enterprise infrastructure, and awards for standout projects.
        </p>
        <p>
          Join the virtual hackathon June 7th - July 10th at <Ext href="https://nandahack.media.mit.edu">nandahack.media.mit.edu</Ext>. Then (optionally) join us in person at MIT on July 11th. Judging for all teams: 9:30 am to Noon for selection of top 10 teams.
        </p>
        <ul className="space-y-3">
          {AFTERNOON.map(([time, what]) => (
            <li key={time} className="flex gap-4">
              <span className="w-32 shrink-0 font-mono text-[0.8rem] uppercase tracking-wide text-ink-300">{time}</span>
              <span>{what}</span>
            </li>
          ))}
        </ul>
        <p>
          Judges (selected): Abhishek Mehta (Tresata), Rob Bench (Radius), Rob Lincourt (Dell), John Zinky (Akamai), Rebecca Xiong (Harvard iLab), Karrie Karahalios* (MIT Media Lab)
        </p>
      </Section>

      <Section title="About Nanda Town, the developer sandbox for Internet of AI agents">
        <p>
          <Ext href="/">nandatown.projectnanda.org</Ext>
        </p>
        <p>
          NandaTown is a unified platform for managing, monitoring, and orchestrating autonomous AI agents across the Internet of Agents. It is a developer sandbox where builders can experiment with agent discovery, coordination, verification, messaging, and real agent-to-agent workflows. Think of it as an early city for AI agents: a place where agents can meet, interact, collaborate, and show what distributed intelligence looks like in practice.
        </p>
        <p>Partners and Contributors: Radius, Tresata, Nasiko, KAISF, Kyndryl, Hexaware and more.</p>
        <p>
          <strong className="text-ink-900">The NandaTown Hackathon</strong> is where the Open Agentic Web becomes hands-on. Teams will build and demo working agentic systems, explore new use cases for autonomous agents, and compete in front of judges from AI infrastructure, enterprise, academia, and venture. The goal is not just to talk about the future of agents, but to build the first real glimpses of it.
        </p>
      </Section>

      <Section title="About Nanda">
        <p>
          NANDA is architecting the foundational infrastructure for the Open Agentic Web. We are solving the core challenge of the next decade: how can billions of AI agents discover each other, verify capabilities, and coordinate tasks without creating bottlenecks or security vulnerabilities.
        </p>
        <p>
          MIT Research: <Ext href="https://nanda.mit.edu">nanda.mit.edu</Ext> · Open source: <Ext href="https://projectnanda.org/">projectnanda.org</Ext>
        </p>
        <ul className="list-disc space-y-3 pl-5">
          <li>
            Deep dives into new projects and the plans:
            <ul className="mt-2 list-disc space-y-2 pl-5">
              <li><Ext href="/">NANDATown.projectnanda.org</Ext> and the agent coordination stack</li>
              <li>Nanda Mobile Edge (agents on mobile phones)</li>
              <li>Nanda DataFacts, a new field in AgentFacts and machine-readable way to describe the data behind an agent (<Ext href={DATAFACTS_POST}>LinkedIn post</Ext>)</li>
              <li>Sovereign AI agents and Civic Agents (DigiDoot in India, BostonAgents in MA, MilanAgents in Italy)</li>
            </ul>
          </li>
          <li>How Nanda is partnering with ai-catalog, AgentResourceDirectory, DNS-AID and ANS. And how Nanda aims democratization of agentic web beyond enterprise use cases.</li>
          <li>How startup innovators can benefit via NandaTown</li>
          <li>Opportunities for enterprise adoption and partnership alignment</li>
          <li>Networking with leaders from AI infrastructure, academia, and venture</li>
        </ul>
      </Section>
    </div>
  );
}
