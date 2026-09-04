import { renderToStaticMarkup } from "react-dom/server";
import { expect, test } from "vitest";
import DocsPage from "../src/app/docs/page";
import { GET as getLlmsTxt } from "../src/app/llms.txt/route";

function expectDiscoveryOnlyCopy(copy: string): void {
  expect(copy).toContain("only makes the catalog entry discoverable");
  expect(copy).toContain(
    "does not verify, install, authorize, endorse, or execute",
  );
  expect(copy).toContain(
    "For new URL and GitHub entries, the catalog stores the source link without fetching or hosting the linked content, agent, or service",
  );
  expect(copy).not.toMatch(
    /\b(?:registry|registration|catalog(?:ing)?|entry)\s+(?:installs?|authorizes?|endorses?|verifies?|hosts?|executes?)\b/i,
  );
  expect(copy).not.toMatch(/\bagents can .*call it in sandbox/i);
}

test("public docs describe SkillMD registration as discovery only", () => {
  const markup = renderToStaticMarkup(<DocsPage />);
  const start = markup.indexOf('<section id="startups"');
  const end = markup.indexOf("</section>", start);

  expect(start).toBeGreaterThanOrEqual(0);
  expect(end).toBeGreaterThan(start);

  const sectionText = markup
    .slice(start, end)
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ");
  expectDiscoveryOnlyCopy(sectionText);
});

test("llms.txt describes the SkillMD registry as discovery only", async () => {
  const response = getLlmsTxt();
  const registryLine = (await response.text())
    .split("\n")
    .find((line) => line.startsWith("- The SkillMD registry"));

  expect(registryLine).toBeTypeOf("string");
  expectDiscoveryOnlyCopy(registryLine ?? "");
});
