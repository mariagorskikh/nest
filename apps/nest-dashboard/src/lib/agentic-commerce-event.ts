/**
 * Single source of truth for Agentic Commerce Hackathon details.
 *
 * Cross-listed from the official Devfolio event page. Project NANDA is a
 * partner sponsor here, not the organizer — update facts from
 * https://agentic-commerce.devfolio.co/overview if Devfolio changes them.
 */

export const agenticCommerceEvent = {
  name: "Agentic Commerce Hackathon",
  tagline:
    "Build AI agents that can discover, decide, and complete transactions.",
  dates: "July 31 – August 2, 2026",
  format: "Online, 48-hour event",
  applyUrl: "https://agentic-commerce.devfolio.co/prizes?partner=Project+Nanda",
  keyTech:
    "Prava is a payments and trust layer that lets AI agents make purchases, available via API/SDK or MCP & CLI.",
  theme:
    'Participants create working products where agents can "shop across merchants, book a trip, manage a subscription, procure software, reserve a table or create a new kind of commerce experience."',
  eligibility:
    "Open to students, developers, designers, operators, researchers, and founders. Build solo or in teams of up to 4 — every team member applies and is accepted individually.",
  participationSteps: [
    "Apply via Devfolio (rolling review basis).",
    "RSVP within 3 days if accepted.",
    "Join the Discord — membership is mandatory.",
    "Build meaningful new work during the hackathon window.",
    "Demonstrate agent-enabled transaction completion using Prava.",
  ],
  prizePool: {
    total: "$73,500+",
    note: "All approved participants also receive $100 in OpenAI credits.",
    breakdown: [
      { sponsor: "Agentic Commerce Hackathon", amount: "$10,000" },
      { sponsor: "OpenAI", amount: "$39,000" },
      { sponsor: "Visa", amount: "$5,000" },
      { sponsor: "Linq", amount: "$6,000" },
      { sponsor: "Localhost", amount: "$5,000" },
      { sponsor: "Project NANDA", amount: "$1,000" },
      { sponsor: "Senso", amount: "$7,500" },
    ],
  },
  pravaTrack: {
    title: "Best Prava Adapter for NANDA Town",
    prize: "$1,000",
    summary:
      "The primary challenge is to build a reliable and reusable Prava payments adapter for NANDA Town, enabling agents to quote, pay, verify transactions, and handle failures using Prava's Agentic Payments Sandbox.",
    stretch:
      "Teams can go further by using their adapter to run commerce simulations involving autonomous buyers, sellers, negotiations, budgets, retries, and other real-world payment conditions.",
    criteria: [
      "Quality and reliability of the adapter",
      "Security, authorization, and failure handling",
      "Ease of installation and reuse",
      "Successful Prava sandbox transactions",
      "Quality of any agentic-commerce scenarios or simulations built on top",
    ],
    closing:
      "The strongest submission should make it easy for future NANDA Town builders to use Prava as a payment layer.",
  },
  judges: [
    { name: "Prof. Ramesh Raskar", affiliation: "MIT Media Labs, Project NANDA founder" },
    { name: "Justin Leung", affiliation: "Visa, Agentic Commerce Principal" },
    { name: "Josh Flayhart", affiliation: "Linq, Staff Engineer" },
    { name: "Ujwal Chaudhari", affiliation: "Visa, Product" },
  ],
} as const;
