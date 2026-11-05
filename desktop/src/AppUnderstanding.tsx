import { useState } from "react";
import type { ContextMismatch, InferResult, OrgContext } from "./types";
import { InferError, inferOrgContext, postOrgContext } from "./lib/orgContext";
import "./AppUnderstanding.css";

// "Here's what we think your app handles". Shown after the founder describes
// their app (and again when the app changes). Plain cards the founder can edit
// or remove, a few simple questions, and any place where their description and
// their code disagree, asked as a question. Nothing is decided silently.

const PAYMENT_SERVICES = ["stripe", "paypal", "paddle", "lemonsqueezy", "lemon squeezy", "square", "braintree", "razorpay", "adyen", "gumroad"];

export function isPaymentService(name: string): boolean {
  const n = name.toLowerCase();
  return PAYMENT_SERVICES.some((p) => n.includes(p));
}

// Plain-words labels for the data kinds Trojan keeps internally.
const PLAIN_KIND: Record<string, string> = {
  pii: "Personal details",
  phi: "Health information",
  payments: "Payment details",
  credentials: "Passwords and keys",
};

export function plainKind(raw: string): string {
  return PLAIN_KIND[raw.trim().toLowerCase()] ?? raw;
}

type Answer = "yes" | "no" | "unsure";

function addLearned(d: OrgContext, fact: string, evidence?: string): OrgContext {
  return { ...d, learned: [...(d.learned ?? []), { fact, evidence, source: "founder" }] };
}

// A mismatch answer: "yes" means the code is right, "no" means the founder's
// description is right. On "no", whatever the code suggested (named in
// `found`) is dropped from the draft.
export function applyMismatchAnswer(d: OrgContext, m: ContextMismatch, answer: Answer): OrgContext {
  if (answer === "unsure") return d;
  let next = d;
  if (answer === "no") {
    const found = m.found.toLowerCase();
    const keep = (s: string) => !found.includes(s.toLowerCase());
    next = {
      ...d,
      third_party_services: (d.third_party_services ?? []).filter(keep),
      data_stores: (d.data_stores ?? []).filter(keep),
    };
    if (found.includes("payment") || (d.third_party_services ?? []).some((s) => found.includes(s.toLowerCase()) && isPaymentService(s))) {
      next = { ...next, third_party_services: (next.third_party_services ?? []).filter((s) => !isPaymentService(s)) };
    }
  }
  return addLearned(next, `${m.question} ${answer === "yes" ? "Yes" : "No"}`, m.found);
}

export function applyQuestionAnswer(d: OrgContext, question: string, answer: Answer): OrgContext {
  if (answer === "unsure") return d;
  return addLearned(d, `${question} ${answer === "yes" ? "Yes" : "No"}`);
}

// ── Editable list ──────────────────────────────────────────────────────────
function ItemList({ items, onChange, label, display = (s) => s, addLabel }: {
  items: string[];
  onChange: (items: string[]) => void;
  label: string;
  display?: (s: string) => string;
  addLabel: string;
}) {
  const [editing, setEditing] = useState<number | null>(null);
  const [text, setText] = useState("");
  const [adding, setAdding] = useState("");

  function commit(i: number) {
    const t = text.trim();
    if (!t) onChange(items.filter((_, j) => j !== i));
    else if (t !== display(items[i])) onChange(items.map((s, j) => (j === i ? t : s)));
    setEditing(null);
  }

  return (
    <div className="au-list" role="list" aria-label={label}>
      {items.map((it, i) => (
        <div className="au-item" role="listitem" key={`${it}-${i}`}>
          {editing === i ? (
            <input
              className="au-input"
              autoFocus
              aria-label={`Change ${display(it)}`}
              value={text}
              onChange={(e) => setText(e.target.value)}
              onBlur={() => commit(i)}
              onKeyDown={(e) => { if (e.key === "Enter") commit(i); }}
            />
          ) : (
            <span className="au-item-text">{display(it)}</span>
          )}
          <button type="button" className="au-link" aria-label={`Edit ${display(it)}`} onClick={() => { setText(display(it)); setEditing(i); }}>Edit</button>
          <button type="button" className="au-link" aria-label={`Remove ${display(it)}`} onClick={() => onChange(items.filter((_, j) => j !== i))}>Remove</button>
        </div>
      ))}
      <form
        className="au-add"
        onSubmit={(e) => {
          e.preventDefault();
          const t = adding.trim();
          if (t) { onChange([...items, t]); setAdding(""); }
        }}
      >
        <input className="au-input" aria-label={addLabel} placeholder={addLabel} value={adding} onChange={(e) => setAdding(e.target.value)} />
        <button type="submit" className="au-link">Add</button>
      </form>
    </div>
  );
}

function YesNo({ value, onChange, name }: { value: Answer | null; onChange: (a: Answer) => void; name: string }) {
  return (
    <div className="au-choices" role="group" aria-label={name}>
      {(["yes", "no", "unsure"] as Answer[]).map((a) => (
        <button
          key={a}
          type="button"
          className={`au-choice ${value === a ? "on" : ""}`}
          aria-pressed={value === a}
          onClick={() => onChange(a)}
        >
          {a === "yes" ? "Yes" : a === "no" ? "No" : "Not sure"}
        </button>
      ))}
    </div>
  );
}

function Card({ title, hint, children, onClear, clearLabel }: {
  title: string; hint?: string; children: React.ReactNode; onClear?: () => void; clearLabel?: string;
}) {
  return (
    <section className="au-card" aria-label={title}>
      <header className="au-card-head">
        <h3 className="au-card-title">{title}</h3>
        {onClear && <button type="button" className="au-link" onClick={onClear} aria-label={clearLabel ?? `Remove ${title}`}>Remove card</button>}
      </header>
      {hint && <p className="au-card-hint">{hint}</p>}
      {children}
    </section>
  );
}

// ── Main component ─────────────────────────────────────────────────────────
type Phase = "start" | "loading" | "review" | "saving";

export function AppUnderstanding({
  serverUrl, projectPath, initialDescription = "", existing, runsFree, onDone, onCancel, onTopUp,
}: {
  serverUrl: string;
  projectPath: string;
  initialDescription?: string;
  /** The context the project already has, if any. */
  existing?: OrgContext | null;
  /** True when this is the project's first look (free). */
  runsFree: boolean;
  onDone: (saved: OrgContext) => void;
  onCancel: () => void;
  /** Opens the existing token purchase screen. */
  onTopUp?: () => void;
}) {
  const [phase, setPhase] = useState<Phase>("start");
  const [description, setDescription] = useState(initialDescription || existing?.app?.description || "");
  const [result, setResult] = useState<InferResult | null>(null);
  const [draft, setDraft] = useState<OrgContext | null>(null);
  const [qAnswers, setQAnswers] = useState<Record<number, Answer>>({});
  const [mAnswers, setMAnswers] = useState<Record<number, Answer>>({});
  const [error, setError] = useState<{ kind: string; message: string } | null>(null);

  async function run() {
    setError(null);
    setPhase("loading");
    try {
      const r = await inferOrgContext(serverUrl, projectPath, description.trim());
      const base: OrgContext = existing ? { ...r.draft, learned: r.draft.learned ?? existing.learned } : r.draft;
      setResult(r);
      setDraft(base);
      setQAnswers({});
      setMAnswers({});
      setPhase("review");
    } catch (e) {
      const ie = e instanceof InferError ? e : new InferError("failed", "Something went wrong. Please try again.");
      setError({ kind: ie.kind, message: ie.message });
      setPhase("start");
    }
  }

  async function save() {
    if (!draft || !result) return;
    // Fold the answers into the draft only now, so changing an answer never
    // stacks up old facts.
    let final = draft;
    result.mismatches.forEach((m, i) => { final = applyMismatchAnswer(final, m, mAnswers[i] ?? "unsure"); });
    result.questions.forEach((q, i) => { final = applyQuestionAnswer(final, q, qAnswers[i] ?? "unsure"); });
    setPhase("saving");
    try {
      await postOrgContext(serverUrl, final, projectPath);
      onDone(final);
    } catch {
      setError({ kind: "failed", message: "Trojan couldn't save this. Please try again." });
      setPhase("review");
    }
  }

  const frame = (children: React.ReactNode) => (
    <div className="au-overlay" role="dialog" aria-modal="true" aria-label="What Trojan knows about your app">
      <div className="au-panel">{children}</div>
    </div>
  );

  if (phase === "start" || phase === "loading") {
    const loading = phase === "loading";
    return frame(
      <>
        <h2 className="au-title">{existing ? "Update what Trojan knows" : "Let Trojan look at your app"}</h2>
        <p className="au-lead">Tell us what your app does in a sentence or two. Trojan will read the names of your pages, data and outside services (never your code) and guess the rest.</p>
        <textarea
          className="au-textarea"
          aria-label="What your app does"
          rows={4}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          disabled={loading}
        />
        {runsFree ? (
          <p className="au-note au-note-free"><strong>Free.</strong> Your first look at an app costs nothing.</p>
        ) : (
          <p className="au-note au-note-cost" role="status">This update uses some of your tokens.</p>
        )}
        {error && (
          <div className="au-error" role="alert">
            <p>{error.kind === "out_of_tokens" ? "You're out of tokens. Add more to keep Trojan learning about your app." : error.message}</p>
            {error.kind === "out_of_tokens" && onTopUp && (
              <button type="button" className="oc-nav-next" onClick={onTopUp}>Add tokens</button>
            )}
          </div>
        )}
        <div className="oc-nav">
          <button type="button" className="oc-nav-back" onClick={onCancel} disabled={loading}>Not now</button>
          <button type="button" className="oc-nav-next" onClick={run} disabled={loading || !description.trim()}>
            {loading ? "Reading your project…" : runsFree ? "Look at my app" : "Update (uses tokens)"}
          </button>
        </div>
      </>,
    );
  }

  if (!draft || !result) return null;
  const set = (patch: Partial<OrgContext>) => setDraft({ ...draft, ...patch });
  const services = draft.third_party_services ?? [];
  const payments = services.filter(isPaymentService);
  const others = services.filter((s) => !isPaymentService(s));
  const auth = draft.auth_model ?? {};
  const setAuth = (patch: Partial<NonNullable<OrgContext["auth_model"]>>) => set({ auth_model: { ...auth, ...patch } });
  const kinds = draft.sensitive_data.map((s) => s.category);

  return frame(
    <>
      <div className="au-head">
        <h2 className="au-title">Here's what we think your app handles</h2>
        {result.free && <span className="au-badge">Free</span>}
      </div>
      <p className="au-lead">Check each card. Fix anything that's wrong or take it out. Nothing is saved until you press Save.</p>

      <div className="au-cards">
        <Card
          title="Information your app handles"
          hint="The kinds of information your users give you."
          onClear={() => set({ sensitive_data: [] })}
        >
          <ItemList
            label="Kinds of information"
            items={kinds}
            display={plainKind}
            addLabel="Add a kind of information"
            onChange={(items) => set({
              sensitive_data: items.map((c) => draft.sensitive_data.find((s) => s.category === c) ?? { category: c }),
            })}
          />
          <p className="au-sub">Where it is kept</p>
          <ItemList
            label="Places data is kept"
            items={draft.data_stores ?? []}
            addLabel="Add a place data is kept"
            onChange={(items) => set({ data_stores: items })}
          />
        </Card>

        <Card title="Who logs in" onClear={() => set({ auth_model: undefined })}>
          <input
            className="au-input"
            aria-label="Who can log in"
            placeholder="For example: customers and staff"
            value={auth.who_logs_in ?? ""}
            onChange={(e) => setAuth({ who_logs_in: e.target.value })}
          />
          <p className="au-sub">Kinds of accounts</p>
          <ItemList label="Kinds of accounts" items={auth.roles ?? []} addLabel="Add a kind of account" onChange={(roles) => setAuth({ roles })} />
        </Card>

        <Card title="Payments" hint="Services your app uses to take money." onClear={() => set({ third_party_services: others })}>
          <ItemList
            label="Payment services"
            items={payments}
            addLabel="Add a payment service"
            onChange={(items) => set({ third_party_services: [...others, ...items] })}
          />
        </Card>

        <Card title="Admin area" onClear={() => setAuth({ admin_area: false })}>
          <label className="au-check">
            <input type="checkbox" checked={Boolean(auth.admin_area)} onChange={(e) => setAuth({ admin_area: e.target.checked })} />
            <span>My app has an area only staff should see</span>
          </label>
        </Card>

        <Card title="Outside services" hint="Other companies' tools your app talks to." onClear={() => set({ third_party_services: payments })}>
          <ItemList
            label="Outside services"
            items={others}
            addLabel="Add an outside service"
            onChange={(items) => set({ third_party_services: [...payments, ...items] })}
          />
        </Card>
      </div>

      {result.mismatches.length > 0 && (
        <div className="au-questions">
          <h3 className="au-card-title">Things that don't match</h3>
          {result.mismatches.map((m, i) => (
            <div className="au-question" key={`m${i}`}>
              <p className="au-q-text">{m.question}</p>
              <p className="au-q-why">You said: {m.said}. We found: {m.found}.</p>
              <YesNo name={m.question} value={mAnswers[i] ?? null} onChange={(a) => setMAnswers({ ...mAnswers, [i]: a })} />
            </div>
          ))}
        </div>
      )}

      {result.questions.length > 0 && (
        <div className="au-questions">
          <h3 className="au-card-title">A few quick questions</h3>
          {result.questions.map((q, i) => (
            <div className="au-question" key={`q${i}`}>
              <p className="au-q-text">{q}</p>
              <YesNo name={q} value={qAnswers[i] ?? null} onChange={(a) => setQAnswers({ ...qAnswers, [i]: a })} />
            </div>
          ))}
        </div>
      )}

      {error && <div className="au-error" role="alert"><p>{error.message}</p></div>}
      <div className="oc-nav">
        <button type="button" className="oc-nav-back" onClick={onCancel}>Not now</button>
        <button type="button" className="oc-nav-next" onClick={save} disabled={phase === "saving"}>
          {phase === "saving" ? "Saving…" : "Save"}
        </button>
      </div>
      <p className="au-note">This stays on your computer, inside your project.</p>
    </>,
  );
}
