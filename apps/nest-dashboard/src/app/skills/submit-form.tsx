"use client";

import { useActionState, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { submitSkill } from "./actions";
import { initialSubmitState } from "./form-state";

type SourceType = "url" | "github" | "content";

const TABS: { key: SourceType; label: string; hint: string }[] = [
  { key: "url", label: "Hosted link", hint: "A public URL to your .md file" },
  { key: "github", label: "GitHub repo", hint: "A link to the repo or file" },
  { key: "content", label: "Paste the file", hint: "Paste the Markdown directly" },
];

const inputClass =
  "w-full rounded-lg border border-cream-400 bg-cream-50 px-4 py-2.5 text-[0.95rem] text-ink-900 placeholder:text-ink-300 outline-none transition-colors focus:border-ink-400 focus:ring-2 focus:ring-ink-900/10";

const labelClass =
  "block font-mono text-[10px] uppercase tracking-[0.18em] text-ink-400 mb-2";

export function SubmitForm() {
  const [state, formAction, pending] = useActionState(
    submitSkill,
    initialSubmitState,
  );
  const [sourceType, setSourceType] = useState<SourceType>("url");
  const formRef = useRef<HTMLFormElement>(null);

  // Clear the fields after a successful save.
  useEffect(() => {
    if (state.ok) {
      formRef.current?.reset();
      setSourceType("url");
    }
  }, [state.ok]);

  return (
    <form ref={formRef} action={formAction} className="space-y-7">
      {/* Name + author */}
      <div className="grid gap-5 sm:grid-cols-2">
        <div>
          <label htmlFor="name" className={labelClass}>
            Skill name <span className="text-rust">*</span>
          </label>
          <input
            id="name"
            name="name"
            required
            placeholder="Weather Lookup"
            className={inputClass}
          />
        </div>
        <div>
          <label htmlFor="author" className={labelClass}>
            Your name or team
          </label>
          <input
            id="author"
            name="author"
            placeholder="Team Rocket"
            className={inputClass}
          />
        </div>
      </div>

      {/* Description */}
      <div>
        <label htmlFor="description" className={labelClass}>
          One line: what does it do?
        </label>
        <input
          id="description"
          name="description"
          placeholder="Gets the current weather for any city."
          className={inputClass}
        />
      </div>

      {/* Source type segmented control */}
      <div>
        <span className={labelClass}>How do you want to submit it?</span>
        <input type="hidden" name="source_type" value={sourceType} />
        <div className="grid gap-2 sm:grid-cols-3">
          {TABS.map((tab) => {
            const active = sourceType === tab.key;
            return (
              <button
                key={tab.key}
                type="button"
                onClick={() => setSourceType(tab.key)}
                className={`rounded-lg border px-4 py-3 text-left transition-colors ${
                  active
                    ? "border-ink-900 bg-ink-900 text-cream-50"
                    : "border-cream-400 bg-cream-50 text-ink-700 hover:border-ink-300"
                }`}
              >
                <span className="block text-[0.9rem] font-medium">
                  {tab.label}
                </span>
                <span
                  className={`mt-0.5 block text-[0.75rem] ${
                    active ? "text-cream-200" : "text-ink-400"
                  }`}
                >
                  {tab.hint}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Conditional source input */}
      {sourceType === "content" ? (
        <div>
          <label htmlFor="content" className={labelClass}>
            SkillMD file <span className="text-rust">*</span>
          </label>
          <textarea
            id="content"
            name="content"
            rows={10}
            placeholder={"# Weather Lookup\n\nGet the current weather for any city.\n\n## Base URL\nhttps://weather.example.com\n..."}
            className={`${inputClass} font-mono text-[0.85rem] leading-relaxed`}
          />
        </div>
      ) : (
        <div>
          <label htmlFor="source_url" className={labelClass}>
            {sourceType === "github" ? "GitHub link" : "Hosted .md link"}{" "}
            <span className="text-rust">*</span>
          </label>
          <input
            id="source_url"
            name="source_url"
            type="url"
            placeholder={
              sourceType === "github"
                ? "https://github.com/you/your-skill"
                : "https://your-site.com/skill.md"
            }
            className={inputClass}
          />
        </div>
      )}

      {/* Endpoints */}
      <div>
        <label htmlFor="endpoints" className={labelClass}>
          Your endpoints
        </label>
        <textarea
          id="endpoints"
          name="endpoints"
          rows={3}
          placeholder={"GET  https://weather.example.com/weather?city={city}\nPOST https://weather.example.com/alerts"}
          className={`${inputClass} font-mono text-[0.85rem] leading-relaxed`}
        />
        <p className="mt-2 text-[0.82rem] text-ink-400">
          The real URLs your skill calls. One per line. These have to be live.
        </p>
      </div>

      {/* Tags */}
      <div>
        <label htmlFor="tags" className={labelClass}>
          Tags
        </label>
        <input
          id="tags"
          name="tags"
          placeholder="weather, api, demo"
          className={inputClass}
        />
      </div>

      {/* Feedback */}
      {state.error && (
        <div className="rounded-lg border border-rust/40 bg-rust/5 px-4 py-3 text-[0.9rem] text-rust">
          {state.error}
        </div>
      )}
      {state.ok && (
        <div className="rounded-lg border border-sage/40 bg-sage/10 px-4 py-3 text-[0.9rem] text-ink-700">
          <strong className="text-ink-900">Saved.</strong> “{state.createdName}”
          is in the registry.{" "}
          {state.createdId && (
            <Link
              href={`/api/skills/${state.createdId}`}
              className="font-medium text-rust underline underline-offset-2 hover:text-ink-900"
            >
              View its API record
            </Link>
          )}
          .
        </div>
      )}

      {/* Submit */}
      <div className="flex items-center gap-4 pt-1">
        <button type="submit" disabled={pending} className="btn-primary disabled:opacity-60">
          {pending ? "Submitting…" : "Submit SkillMD"}
        </button>
        <span className="text-[0.82rem] text-ink-400">
          Saved to the Nanda Town registry.
        </span>
      </div>
    </form>
  );
}
