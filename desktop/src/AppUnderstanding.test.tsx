import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { AppUnderstanding, applyMismatchAnswer } from "./AppUnderstanding";
import { ContextChangeBanner } from "./ContextChangeBanner";
import { normalizeOrgContext } from "./lib/orgContext";
import type { InferResult, OrgContext } from "./types";

const draft: OrgContext = {
  app: { name: "Shop", description: "A small shop" },
  sensitive_data: [{ category: "PII" }, { category: "Payments" }],
  trust_boundaries: [],
  threat_actors: [],
  data_stores: ["orders", "profiles"],
  auth_model: { who_logs_in: "customers and staff", roles: ["customer", "admin"], admin_area: true },
  third_party_services: ["stripe", "supabase"],
};

function result(over: Partial<InferResult> = {}): InferResult {
  return {
    draft,
    questions: ["Do customers upload files?"],
    mismatches: [{ said: "no payments", found: "stripe", question: "Does your app take payments?" }],
    free: true,
    ...over,
  };
}

let posted: OrgContext | null;
function mockFetch(inferStatus: number, body: unknown) {
  posted = null;
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    if (url.includes("/api/context/infer")) {
      return new Response(JSON.stringify(body), { status: inferStatus });
    }
    if (url.includes("/api/context") && init?.method === "POST") {
      posted = JSON.parse(String(init.body));
      return new Response(JSON.stringify({ ok: true, path: "/p/.trojan/context.yaml" }), { status: 200 });
    }
    return new Response("{}", { status: 404 });
  }));
}

async function reachReview(runsFree = true) {
  const onDone = vi.fn();
  render(<AppUnderstanding serverUrl="http://x" projectPath="/p" initialDescription="A small shop" runsFree={runsFree} onDone={onDone} onCancel={() => {}} />);
  fireEvent.click(screen.getByRole("button", { name: runsFree ? "Look at my app" : /Update/ }));
  await screen.findByText("Here's what we think your app handles");
  return onDone;
}

beforeEach(() => mockFetch(200, { draft, questions: result().questions, mismatches: result().mismatches, free: true }));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe("AppUnderstanding", () => {
  it("renders plain cards from the draft", async () => {
    await reachReview();
    expect(screen.getByText("Information your app handles")).toBeTruthy();
    expect(screen.getByText("Personal details")).toBeTruthy(); // PII shown in plain words
    expect(screen.queryByText("PII")).toBeNull();
    expect(screen.getByText("orders")).toBeTruthy();
    expect(screen.getByDisplayValue("customers and staff")).toBeTruthy();
    expect(screen.getByText("Payments")).toBeTruthy();
    expect(screen.getByText("Admin area")).toBeTruthy();
    expect(screen.getByText("Outside services")).toBeTruthy();
    expect(screen.getByText("Free")).toBeTruthy();
  });

  it("removing and editing items changes what gets saved", async () => {
    await reachReview();
    fireEvent.click(screen.getByLabelText("Remove orders"));
    fireEvent.click(screen.getByLabelText("Remove supabase"));
    fireEvent.change(screen.getByLabelText("Who can log in"), { target: { value: "only staff" } });
    fireEvent.change(screen.getByLabelText("Add an outside service"), { target: { value: "sendgrid" } });
    const adds = screen.getAllByText("Add");
    fireEvent.click(adds[adds.length - 1]);
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(posted).not.toBeNull());
    expect(posted!.data_stores).toEqual(["profiles"]);
    expect(posted!.auth_model?.who_logs_in).toBe("only staff");
    expect(posted!.third_party_services).toEqual(["stripe", "sendgrid"]);
  });

  it("answering a mismatch with No drops what the code suggested", async () => {
    const onDone = await reachReview();
    const group = screen.getByRole("group", { name: "Does your app take payments?" });
    fireEvent.click(group.querySelectorAll("button")[1]); // No
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(posted!.third_party_services).toEqual(["supabase"]);
    expect(posted!.learned?.[0]).toMatchObject({ fact: "Does your app take payments? No", source: "founder" });
  });

  it("answering Yes keeps it and records the answer", async () => {
    await reachReview();
    const group = screen.getByRole("group", { name: "Does your app take payments?" });
    fireEvent.click(group.querySelectorAll("button")[0]);
    const q = screen.getByRole("group", { name: "Do customers upload files?" });
    fireEvent.click(q.querySelectorAll("button")[0]);
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(posted).not.toBeNull());
    expect(posted!.third_party_services).toContain("stripe");
    expect(posted!.learned?.map((l) => l.fact)).toEqual(["Does your app take payments? Yes", "Do customers upload files? Yes"]);
  });

  it("tells them before running when an update uses tokens", () => {
    render(<AppUnderstanding serverUrl="http://x" projectPath="/p" existing={draft} runsFree={false} onDone={() => {}} onCancel={() => {}} />);
    expect(screen.getByRole("status").textContent).toMatch(/uses some of your tokens/);
    expect(screen.queryByText(/Your first look/)).toBeNull();
  });

  it("shows the out of tokens message with a way to add tokens", async () => {
    mockFetch(402, { error: "out_of_tokens", message: "You're out of tokens. Add more to keep Trojan learning about your app." });
    const onTopUp = vi.fn();
    render(<AppUnderstanding serverUrl="http://x" projectPath="/p" initialDescription="d" runsFree={false} onDone={() => {}} onCancel={() => {}} onTopUp={onTopUp} />);
    fireEvent.click(screen.getByRole("button", { name: /Update/ }));
    expect(await screen.findByRole("alert")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Add tokens" }));
    expect(onTopUp).toHaveBeenCalled();
  });
});

describe("applyMismatchAnswer", () => {
  it("is a no-op for Not sure", () => {
    expect(applyMismatchAnswer(draft, { said: "a", found: "stripe", question: "q" }, "unsure")).toBe(draft);
  });
});

describe("normalizeOrgContext", () => {
  it("keeps the inferred fields", () => {
    const n = normalizeOrgContext(draft);
    expect(n.data_stores).toEqual(["orders", "profiles"]);
    expect(n.auth_model?.admin_area).toBe(true);
    expect(n.third_party_services).toEqual(["stripe", "supabase"]);
  });
});

describe("ContextChangeBanner", () => {
  it("offers an update when the app changed, and says updates use tokens", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      if (url.includes("/api/context/changes")) {
        return new Response(JSON.stringify({ has_snapshot: true, changed: true, changes: {
          routes_added: ["POST /api/refunds"], routes_removed: [], data_stores_added: ["refunds"], data_stores_removed: [], services_added: [], services_removed: [],
        } }));
      }
      return new Response(JSON.stringify({ exists: true, context: draft }));
    }));
    render(<ContextChangeBanner serverUrl="http://x" projectPath="/p" />);
    expect(await screen.findByText(/Your app changed since Trojan last learned about it/)).toBeTruthy();
    expect(screen.getByText("New pages: /api/refunds")).toBeTruthy();
    expect(screen.getByText("Updates use tokens.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Update what Trojan knows" }));
    expect(await screen.findByText(/uses some of your tokens/)).toBeTruthy();
  });

  it("shows nothing when nothing changed", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      if (url.includes("/api/context/changes")) return new Response(JSON.stringify({ has_snapshot: true, changed: false, changes: {} }));
      return new Response(JSON.stringify({ exists: true, context: draft }));
    }));
    render(<ContextChangeBanner serverUrl="http://x" projectPath="/p" />);
    await waitFor(() => expect((fetch as unknown as ReturnType<typeof vi.fn>).mock.calls.length).toBe(2));
    expect(screen.queryByRole("status")).toBeNull();
  });
});
