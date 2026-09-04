// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SubmitForm } from "@/app/skills/submit-form";
import { submitSkill } from "@/app/skills/actions";
import { initialSubmitState, type SubmitState } from "@/app/skills/form-state";

// Keep the actual form, React action queue and DOM events. Replace only the
// server boundary: these tests must not probe a URL or write a live catalog.
vi.mock("@/app/skills/actions", () => ({ submitSkill: vi.fn() }));

let container: HTMLDivElement;
let root: Root;

beforeEach(async () => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.mocked(submitSkill).mockReset();
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
  await act(async () => root.render(<SubmitForm />));
});

afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
});

function form() {
  return container.querySelector("form")!;
}

function submitButton() {
  return container.querySelector<HTMLButtonElement>('button[type="submit"]')!;
}

function fillName(name: string) {
  container.querySelector<HTMLInputElement>('[name="name"]')!.value = name;
}

const rejected: SubmitState = {
  ok: false, error: "Please correct the source.", createdId: null, createdName: null,
};

describe("SkillMD form submission lifecycle", () => {
  it("does not queue a second action when submit events arrive before the pending render", async () => {
    let finish!: (value: SubmitState) => void;
    vi.mocked(submitSkill).mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; }));
    vi.mocked(submitSkill).mockResolvedValue(rejected);
    fillName("First skill");

    await act(async () => {
      // Equivalent submit events from repeated requestSubmit calls. A disabled
      // button is not the sole path into a form action.
      form().requestSubmit();
      form().requestSubmit();
    });
    expect(submitButton().disabled).toBe(true);
    await act(async () => finish(rejected));
    // Count after the first settles so React cannot hide a queued duplicate.
    expect(submitSkill).toHaveBeenCalledTimes(1);
    expect(vi.mocked(submitSkill).mock.calls[0][1].get("name")).toBe("First skill");
    expect(container.textContent).toContain("Please correct the source.");
    expect(submitButton().disabled).toBe(false);

    fillName("Corrected skill");
    await act(async () => form().requestSubmit());
    expect(submitSkill).toHaveBeenCalledTimes(2);
    expect(vi.mocked(submitSkill).mock.calls[1][1].get("name")).toBe("Corrected skill");
  });

  it("does not admit another submit while an earlier action is still pending", async () => {
    let finish!: (value: SubmitState) => void;
    vi.mocked(submitSkill).mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; }));
    vi.mocked(submitSkill).mockResolvedValue(rejected);
    fillName("Pending skill");
    await act(async () => form().requestSubmit());
    await act(async () => form().requestSubmit());
    await act(async () => finish(rejected));
    expect(submitSkill).toHaveBeenCalledTimes(1);
  });

  it("permits correction after an immediately resolved validation failure", async () => {
    vi.mocked(submitSkill).mockResolvedValue(rejected);
    fillName("Invalid skill");
    await act(async () => form().requestSubmit());
    expect(container.textContent).toContain("Please correct the source.");
    fillName("Retried skill");
    await act(async () => form().requestSubmit());
    expect(submitSkill).toHaveBeenCalledTimes(2);
    expect(vi.mocked(submitSkill).mock.calls[0][0]).toEqual(initialSubmitState);
    expect(vi.mocked(submitSkill).mock.calls[1][0]).toEqual(rejected);
    expect(vi.mocked(submitSkill).mock.calls[1][1].get("name")).toBe("Retried skill");
    expect(submitButton().disabled).toBe(false);
  });

  it("does not lock the form when native validation prevents submission", async () => {
    vi.mocked(submitSkill).mockResolvedValue(rejected);
    await act(async () => form().requestSubmit());
    expect(submitSkill).not.toHaveBeenCalled();
    fillName("Now valid");
    await act(async () => form().requestSubmit());
    expect(submitSkill).toHaveBeenCalledTimes(1);
  });

  it.each(["immediate", "delayed"])("permits a new submission after %s success", async (timing) => {
    const first: SubmitState = { ok: true, error: null, createdId: "first", createdName: "First skill" };
    const second: SubmitState = { ok: true, error: null, createdId: "second", createdName: "Second skill" };
    let finish!: (value: SubmitState) => void;
    if (timing === "delayed") {
      vi.mocked(submitSkill).mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; }));
    } else {
      vi.mocked(submitSkill).mockResolvedValueOnce(first);
    }
    vi.mocked(submitSkill).mockResolvedValueOnce(second);
    fillName("First skill");
    await act(async () => form().requestSubmit());
    if (timing === "delayed") await act(async () => finish(first));
    expect(container.textContent).toContain("First skill");
    expect(container.querySelector<HTMLInputElement>('[name="name"]')!.value).toBe("");
    fillName("Second skill");
    await act(async () => form().requestSubmit());
    expect(submitSkill).toHaveBeenCalledTimes(2);
    expect(vi.mocked(submitSkill).mock.calls[1][1].get("name")).toBe("Second skill");
    expect(container.querySelector('a[href="/api/skills/second"]')).not.toBeNull();
    expect(submitButton().disabled).toBe(false);
  });
});
