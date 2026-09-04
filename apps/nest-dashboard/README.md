This is a [Next.js](https://nextjs.org) project bootstrapped with [`create-next-app`](https://nextjs.org/docs/app/api-reference/cli/create-next-app).

## Getting Started

First, run the development server:

```bash
npm run dev
# or
yarn dev
# or
pnpm dev
# or
bun dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.

You can start editing the page by modifying `app/page.tsx`. The page auto-updates as you edit the file.

This project uses [`next/font`](https://nextjs.org/docs/app/building-your-application/optimizing/fonts) to automatically optimize and load [Geist](https://vercel.com/font), a new font family for Vercel.

## Catalog regression tests

Use Node 22.12+ (CI uses Node 22), then run:

```bash
npm ci --ignore-scripts
npm test
npm run typecheck
```

The tests exercise the real API handler, form action and rendered page with
external persistence and request context replaced by test doubles. Unexpected
network access is blocked. They require no database, credentials or live
endpoint. They do not prove database transactions, browser hydration or a
deployed Next server.

The form lifecycle tests use the real React action queue and a DOM environment,
with only the server action replaced. They cover repeated submit events, pending
submissions, validation retries and new submissions after success. The guard
prevents re-entry in one mounted form; it does not deduplicate separate tabs,
HTTP retries or concurrent server requests. Server idempotency needs a separate
contract with an explicit operation key and atomic persistence. A time-window
lookup before insertion is not that guarantee.

URL validation checks source syntax only. API and form submissions do not probe
links and keep `reachable: null`; the page labels those links as not checked.
A saved catalog record is not evidence that a link is live or safe, an
endorsement, or permission to execute a submitted skill.

## Learn More

To learn more about Next.js, take a look at the following resources:

- [Next.js Documentation](https://nextjs.org/docs) - learn about Next.js features and API.
- [Learn Next.js](https://nextjs.org/learn) - an interactive Next.js tutorial.

You can check out [the Next.js GitHub repository](https://github.com/vercel/next.js) - your feedback and contributions are welcome!

## Deploy on Vercel

The easiest way to deploy your Next.js app is to use the [Vercel Platform](https://vercel.com/new?utm_medium=default-template&filter=next.js&utm_source=create-next-app&utm_campaign=create-next-app-readme) from the creators of Next.js.

Check out our [Next.js deployment documentation](https://nextjs.org/docs/app/building-your-application/deploying) for more details.
