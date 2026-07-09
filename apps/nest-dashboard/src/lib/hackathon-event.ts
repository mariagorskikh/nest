/**
 * Single source of truth for NandaHack event details.
 *
 * Cross-listed from the official hackathon site. Update dates here and
 * every page — banner, homepage, hackathon page, footer — picks them up.
 */

export const hackathonEvent = {
  name: "NandaHack",
  tagline: "An agentic AI hackathon by Project NANDA, HCLTech, and MIT Media Lab.",
  officialUrl: "https://nandahack.media.mit.edu",
  repoUrl: "https://github.com/projnanda/nandatown",
  githubPRsUrl: "https://github.com/projnanda/nandatown/pulls",
  virtualWindow: "June 7 – July 10",
  submissionDeadline: "Friday, July 10 · 12:00 PM ET",
  finale: "Saturday, July 11 · MIT Media Lab, Boston",
} as const;

export type FaqEntry = { question: string; answer: string };

export const hackathonFaqs: FaqEntry[] = [
  {
    question: "Can my team participate virtually?",
    answer:
      "Yes — fully. The hackathon runs virtually from June 7 to July 10, so you can build from anywhere in the world. You don't even need to register on Luma to take part virtually; only in-person finale attendance needs a ticket.",
  },
  {
    question: "When are submissions due?",
    answer:
      "All submissions are due Friday, July 10 at 12:00 PM (noon) ET — no matter where you're building from.",
  },
  {
    question: "Do I have to come to MIT for the finale?",
    answer:
      "No. The Nanda Summit & finale on Saturday, July 11 at MIT Media Lab is optional, and attendance does not affect your score. There's no coding or building at the in-person event — only demos and meeting other builders.",
  },
  {
    question: "What do teams build?",
    answer:
      "Agentic AI applications in the Nanda Town sandbox using the SKILL.md framework — protocols and plugins across the twelve layers. Submit by opening a PR on GitHub with the branch name hackathon/<handle>-<theme>.",
  },
  {
    question: "How does judging work?",
    answer:
      "A judge panel scores each submission on correctness, realism, design, and docs. On July 11, judging runs 9:30 AM to noon to select the top 10 teams, with demos and sessions from 2 to 5 PM.",
  },
];
