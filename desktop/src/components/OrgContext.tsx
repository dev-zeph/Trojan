import { useEffect, useRef, useState } from "react";
import type {
  OrgContext,
  SensitiveDataCategory,
  TrustBoundary,
  ThreatActor,
} from "../types";
import {
  emptyOrgContext,
  orgContextHasContent,
  fetchOrgContext,
  postOrgContext,
  loadContextDraft,
  saveContextDraft,
} from "../lib/orgContext";
import { CM } from "./CornerMarks";

// OrgContext.tsx renders the authored, project-local security-and-privacy
// context: what the user is building, the sensitive data it handles, its trust
// boundaries, and the threat actors it defends against. Trojan uses this to
// test intentionally instead of generically. It is stored on the user's
// machine (the project's .trojan/context.yaml), never uploaded to Trojan.
//
// Three exports:
//   - OrgContextWizard: the guided, multi-step onboarding flow.
//   - OrgContextEditor: the settings surface to view and edit it any time.
//   - LocalPrivacyBadge: the small reusable "stays on your machine" callout.

// ── Presets ────────────────────────────────────────────────────────────────
const SENSITIVE_PRESETS: { category: string; description: string }[] = [
  { category: "PII", description: "Names, emails, addresses, and other personal identifiers." },
  { category: "PHI", description: "Health records and other protected health information." },
  { category: "Payments", description: "Card numbers, bank details, and transaction data." },
  { category: "Credentials", description: "Passwords, API keys, tokens, and secrets." },
];
const BOUNDARY_PRESETS: { name: string; description: string }[] = [
  { name: "Public API", description: "Reachable by anyone on the internet, no login required." },
  { name: "Authenticated app", description: "Behind a login, available to any signed-in user." },
  { name: "Internal admin", description: "Restricted to staff or operators." },
  { name: "Background jobs", description: "Queues, workers, and scheduled tasks." },
];
const ACTOR_PRESETS: { name: string; description: string }[] = [
  { name: "External attacker", description: "An unauthenticated stranger probing from the internet." },
  { name: "Malicious tenant", description: "A real user trying to reach another tenant's data." },
  { name: "Malicious insider", description: "Someone with legitimate but limited access." },
  { name: "Automated bot", description: "Scrapers and credential-stuffing scripts." },
];

// ── Small field primitives ──────────────────────────────────────────────────
function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <label className="oc-field">
      <span className="oc-field-label">{label}</span>
      {children}
      {hint && <span className="oc-field-hint">{hint}</span>}
    </label>
  );
}

// A chip-style multi-value input. Enter or comma commits a value; each value
// can be removed. Used for glob file patterns, symbol regexes, and actor
// targets, all of which are optional and repeatable.
function ChipListInput({ values, onChange, placeholder }: {
  values: string[];
  onChange: (v: string[]) => void;
  placeholder?: string;
}) {
  const [draft, setDraft] = useState("");
  function commit() {
    const v = draft.trim();
    if (v && !values.includes(v)) onChange([...values, v]);
    setDraft("");
  }
  return (
    <div className="oc-chips">
      {values.map((v, i) => (
        <span className="oc-chip" key={`${v}-${i}`}>
          <code>{v}</code>
          <button type="button" className="oc-chip-rm" aria-label={`Remove ${v}`} onClick={() => onChange(values.filter((_, j) => j !== i))}>x</button>
        </span>
      ))}
      <input
        className="oc-chip-input"
        value={draft}
        placeholder={values.length === 0 ? placeholder : "add another"}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === ",") { e.preventDefault(); commit(); }
          else if (e.key === "Backspace" && !draft && values.length) onChange(values.slice(0, -1));
        }}
        onBlur={commit}
      />
    </div>
  );
}

// ── Section editors ─────────────────────────────────────────────────────────
function AppSection({ value, onChange }: { value: OrgContext; onChange: (c: OrgContext) => void }) {
  return (
    <div className="oc-section">
      <Field label="APP NAME">
        <input
          className="oc-input"
          placeholder="e.g. Acme Health Portal"
          value={value.app.name}
          onChange={(e) => onChange({ ...value, app: { ...value.app, name: e.target.value } })}
        />
      </Field>
      <Field
        label="WHAT ARE YOU BUILDING?"
        hint="One paragraph in your own words: what it does, who uses it, and why it exists. This single field is what lets Trojan test intentionally instead of generically."
      >
        <textarea
          className="oc-textarea"
          rows={5}
          placeholder="A patient-facing portal where people book appointments and view lab results. Clinicians sign in to review records. It integrates with a third-party billing provider."
          value={value.app.description}
          onChange={(e) => onChange({ ...value, app: { ...value.app, description: e.target.value } })}
        />
      </Field>
    </div>
  );
}

function SensitiveSection({ value, onChange }: { value: OrgContext; onChange: (c: OrgContext) => void }) {
  const items = value.sensitive_data;
  const set = (next: SensitiveDataCategory[]) => onChange({ ...value, sensitive_data: next });
  const has = (c: string) => items.some((i) => i.category.toLowerCase() === c.toLowerCase());
  return (
    <div className="oc-section">
      <div className="oc-presets">
        {SENSITIVE_PRESETS.map((p) => (
          <button
            key={p.category}
            type="button"
            className={`oc-preset ${has(p.category) ? "on" : ""}`}
            onClick={() => has(p.category)
              ? set(items.filter((i) => i.category.toLowerCase() !== p.category.toLowerCase()))
              : set([...items, { category: p.category, description: p.description }])}
          >
            {has(p.category) ? "✓ " : "+ "}{p.category}
          </button>
        ))}
      </div>
      {items.map((it, idx) => {
        const upd = (patch: Partial<SensitiveDataCategory>) => set(items.map((x, j) => j === idx ? { ...x, ...patch } : x));
        return (
          <div className="oc-entry" key={idx}>
            <CM />
            <button type="button" className="oc-entry-rm" aria-label="Remove category" onClick={() => set(items.filter((_, j) => j !== idx))}>x</button>
            <Field label="CATEGORY">
              <input className="oc-input" placeholder="PII, PHI, payments, credentials..." value={it.category} onChange={(e) => upd({ category: e.target.value })} />
            </Field>
            <Field label="DESCRIPTION" hint="Optional. What this data is, in plain words.">
              <input className="oc-input" placeholder="Customer names and emails" value={it.description ?? ""} onChange={(e) => upd({ description: e.target.value })} />
            </Field>
            <Field label="FILE PATTERNS" hint="Optional. Globs that locate this data (e.g. internal/billing/**).">
              <ChipListInput values={it.file_patterns ?? []} onChange={(v) => upd({ file_patterns: v })} placeholder="internal/billing/**" />
            </Field>
            <Field label="SYMBOL PATTERNS" hint="Optional. Regexes matched against symbol names (e.g. (?i)ssn|card).">
              <ChipListInput values={it.symbol_patterns ?? []} onChange={(v) => upd({ symbol_patterns: v })} placeholder="(?i)ssn|card" />
            </Field>
          </div>
        );
      })}
      <button type="button" className="oc-add" onClick={() => set([...items, { category: "" }])}>+ Add a category</button>
    </div>
  );
}

function BoundarySection({ value, onChange }: { value: OrgContext; onChange: (c: OrgContext) => void }) {
  const items = value.trust_boundaries;
  const set = (next: TrustBoundary[]) => onChange({ ...value, trust_boundaries: next });
  const has = (n: string) => items.some((i) => i.name.toLowerCase() === n.toLowerCase());
  return (
    <div className="oc-section">
      <div className="oc-presets">
        {BOUNDARY_PRESETS.map((p) => (
          <button
            key={p.name}
            type="button"
            className={`oc-preset ${has(p.name) ? "on" : ""}`}
            onClick={() => has(p.name)
              ? set(items.filter((i) => i.name.toLowerCase() !== p.name.toLowerCase()))
              : set([...items, { name: p.name, description: p.description }])}
          >
            {has(p.name) ? "✓ " : "+ "}{p.name}
          </button>
        ))}
      </div>
      {items.map((it, idx) => {
        const upd = (patch: Partial<TrustBoundary>) => set(items.map((x, j) => j === idx ? { ...x, ...patch } : x));
        return (
          <div className="oc-entry" key={idx}>
            <CM />
            <button type="button" className="oc-entry-rm" aria-label="Remove boundary" onClick={() => set(items.filter((_, j) => j !== idx))}>x</button>
            <Field label="BOUNDARY">
              <input className="oc-input" placeholder="public API, internal admin..." value={it.name} onChange={(e) => upd({ name: e.target.value })} />
            </Field>
            <Field label="DESCRIPTION" hint="Optional. Who can reach this zone, and how.">
              <input className="oc-input" placeholder="Reachable by anyone, no login required" value={it.description ?? ""} onChange={(e) => upd({ description: e.target.value })} />
            </Field>
            <Field label="FILE PATTERNS" hint="Optional. Globs that locate code in this zone.">
              <ChipListInput values={it.file_patterns ?? []} onChange={(v) => upd({ file_patterns: v })} placeholder="cmd/adminserver/**" />
            </Field>
            <Field label="SYMBOL PATTERNS" hint="Optional. Regexes for handler/route naming (e.g. (?i)^Handle).">
              <ChipListInput values={it.symbol_patterns ?? []} onChange={(v) => upd({ symbol_patterns: v })} placeholder="(?i)^Admin" />
            </Field>
          </div>
        );
      })}
      <button type="button" className="oc-add" onClick={() => set([...items, { name: "" }])}>+ Add a boundary</button>
    </div>
  );
}

function ActorSection({ value, onChange }: { value: OrgContext; onChange: (c: OrgContext) => void }) {
  const items = value.threat_actors;
  const set = (next: ThreatActor[]) => onChange({ ...value, threat_actors: next });
  const has = (n: string) => items.some((i) => i.name.toLowerCase() === n.toLowerCase());
  const boundaryNames = value.trust_boundaries.map((b) => b.name).filter(Boolean);
  return (
    <div className="oc-section">
      <div className="oc-presets">
        {ACTOR_PRESETS.map((p) => (
          <button
            key={p.name}
            type="button"
            className={`oc-preset ${has(p.name) ? "on" : ""}`}
            onClick={() => has(p.name)
              ? set(items.filter((i) => i.name.toLowerCase() !== p.name.toLowerCase()))
              : set([...items, { name: p.name, description: p.description }])}
          >
            {has(p.name) ? "✓ " : "+ "}{p.name}
          </button>
        ))}
      </div>
      {items.map((it, idx) => {
        const upd = (patch: Partial<ThreatActor>) => set(items.map((x, j) => j === idx ? { ...x, ...patch } : x));
        return (
          <div className="oc-entry" key={idx}>
            <CM />
            <button type="button" className="oc-entry-rm" aria-label="Remove actor" onClick={() => set(items.filter((_, j) => j !== idx))}>x</button>
            <Field label="ACTOR">
              <input className="oc-input" placeholder="external attacker, malicious tenant..." value={it.name} onChange={(e) => upd({ name: e.target.value })} />
            </Field>
            <Field label="DESCRIPTION" hint="Optional. What this actor can do and wants.">
              <input className="oc-input" placeholder="A signed-in user trying to reach another user's data" value={it.description ?? ""} onChange={(e) => upd({ description: e.target.value })} />
            </Field>
            <Field label="TARGETS" hint={boundaryNames.length ? `Optional. Which boundaries this actor can reach (${boundaryNames.join(", ")}).` : "Optional. Which boundaries this actor can reach. Define boundaries first to reference them."}>
              <ChipListInput values={it.targets ?? []} onChange={(v) => upd({ targets: v })} placeholder="public API" />
            </Field>
          </div>
        );
      })}
      <button type="button" className="oc-add" onClick={() => set([...items, { name: "" }])}>+ Add an actor</button>
    </div>
  );
}

// ── Reusable local-only privacy badge ───────────────────────────────────────
export function LocalPrivacyBadge({ compact }: { compact?: boolean }) {
  return (
    <div className={`oc-privacy-badge ${compact ? "compact" : ""}`}>
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" />
      </svg>
      <span>
        {compact
          ? "Stored on your machine. Never uploaded to Trojan."
          : "This context is written to your project (.trojan/context.yaml) and stays on your machine. Trojan never uploads it to the cloud."}
      </span>
    </div>
  );
}

// ── Onboarding wizard ────────────────────────────────────────────────────────
type WizardStep = { key: string; eyebrow: string; title: string; blurb: string; render: () => React.ReactNode };

export function OrgContextWizard({ initial, onFinish, onSkip }: {
  initial?: OrgContext | null;
  onFinish: (ctx: OrgContext) => void;
  onSkip: () => void;
}) {
  const [ctx, setCtx] = useState<OrgContext>(initial && orgContextHasContent(initial) ? initial : emptyOrgContext());
  const [step, setStep] = useState(0);

  const steps: WizardStep[] = [
    { key: "app", eyebrow: "STEP 1 OF 4", title: "What are you building?", blurb: "Describe your app the way you would to a new teammate. This is the highest-value thing you can tell Trojan.", render: () => <AppSection value={ctx} onChange={setCtx} /> },
    { key: "sensitive", eyebrow: "STEP 2 OF 4", title: "What sensitive data does it handle?", blurb: "Tap the kinds of data your app touches. Trojan tests these paths harder for both security and privacy.", render: () => <SensitiveSection value={ctx} onChange={setCtx} /> },
    { key: "boundaries", eyebrow: "STEP 3 OF 4", title: "Where are your trust boundaries?", blurb: "The zones with different levels of trust. This is how Trojan reasons about who can reach what.", render: () => <BoundarySection value={ctx} onChange={setCtx} /> },
    { key: "actors", eyebrow: "STEP 4 OF 4", title: "Who are you defending against?", blurb: "The attackers you actually care about. Trojan prioritizes the paths they would take.", render: () => <ActorSection value={ctx} onChange={setCtx} /> },
  ];

  const isLast = step === steps.length - 1;
  const canAdvance = step > 0 || ctx.app.name.trim().length > 0 || ctx.app.description.trim().length > 0;
  const cur = steps[step];

  return (
    <div className="ob-split">
      {/* Left: the privacy story, kept in view the whole way through. */}
      <div className="ob-left">
        <div className="ob-left-center">
          <img src="/logo.png" alt="Trojan" className="ob-left-logo" />
          <span className="ob-left-wordmark">TROJAN</span>
          <p className="ob-left-tagline">
            Trojan is smarter than a generic scanner because you tell it what you are building. It tests intentionally, for security and privacy, against your own model.
          </p>
          <div className="oc-privacy-panel">
            <div className="oc-privacy-panel-head">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
                <rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" />
              </svg>
              This never leaves your machine
            </div>
            <p className="oc-privacy-panel-body">
              Everything here is saved locally in your project (.trojan/context.yaml). Trojan never uploads it. You stay in control, and you can edit or delete it any time.
            </p>
          </div>
        </div>
        <div className="ob-left-bottom">
          <div className="oc-wizard-progress">
            {steps.map((s, i) => (
              <button
                key={s.key}
                type="button"
                className={`oc-wizard-dot ${i === step ? "on" : ""} ${i < step ? "done" : ""}`}
                onClick={() => setStep(i)}
                aria-label={`Go to ${s.title}`}
              />
            ))}
          </div>
          <div className="ob-left-ver">Set up local context</div>
        </div>
      </div>

      {/* Right: the current step. */}
      <div className="ob-right">
        <div className="ob-right-card oc-wizard-card">
          <i className="corner-mark cm-tl">+</i>
          <i className="corner-mark cm-tr">+</i>
          <i className="corner-mark cm-bl">+</i>
          <i className="corner-mark cm-br">+</i>

          <span className="oc-wizard-eyebrow">{cur.eyebrow}</span>
          <span className="ob-right-title" style={{ marginBottom: 6 }}>{cur.title}</span>
          <p className="oc-wizard-blurb">{cur.blurb}</p>

          <div className="oc-wizard-body">{cur.render()}</div>

          <div className="oc-nav">
            {step > 0
              ? <button type="button" className="oc-nav-back" onClick={() => setStep((s) => s - 1)}>{"←"} Back</button>
              : <span />}
            {isLast
              ? <button type="button" className="oc-nav-next" onClick={() => onFinish(ctx)}>Save context {"→"}</button>
              : <button type="button" className="oc-nav-next" disabled={!canAdvance} onClick={() => setStep((s) => s + 1)}>Continue {"→"}</button>}
          </div>

          <div className="ob-footer-sep">
            <button type="button" className="ob-footer-skip" onClick={onSkip}>Skip for now, set this up later</button>
            <span className="ob-footer-note">You can add or edit this any time from Project Context.</span>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Settings editor ──────────────────────────────────────────────────────────
type LoadState = "idle" | "loading" | "ready" | "error";

export function OrgContextEditor({ serverUrl }: { serverUrl: string | null }) {
  const [ctx, setCtx] = useState<OrgContext>(emptyOrgContext());
  const [loadState, setLoadState] = useState<LoadState>("idle");
  const [projectPath, setProjectPath] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [savedFlash, setSavedFlash] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const loadedForUrl = useRef<string | null>(null);

  // Load: prefer the live project context from the server; fall back to the
  // local draft when no scan server is running (e.g. straight after onboarding).
  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoadState("loading");
      setError(null);
      const draft = await loadContextDraft();
      if (serverUrl) {
        try {
          const { exists, context } = await fetchOrgContext(serverUrl);
          if (cancelled) return;
          setCtx(exists && context ? context : (draft ?? emptyOrgContext()));
          setLoadState("ready");
          loadedForUrl.current = serverUrl;
          return;
        } catch {
          // server not ready / endpoint absent -- fall through to the draft
        }
      }
      if (cancelled) return;
      setCtx(draft ?? emptyOrgContext());
      setLoadState("ready");
    }
    load();
    return () => { cancelled = true; };
  }, [serverUrl]);

  // Learn the current project's path (for the header) from the running scan.
  useEffect(() => {
    if (!serverUrl) { setProjectPath(null); return; }
    let cancelled = false;
    fetch(`${serverUrl}/api/scans/latest`)
      .then((r) => r.ok ? r.json() : null)
      .then((d) => { if (!cancelled && d?.project_path) setProjectPath(d.project_path); })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [serverUrl]);

  function update(next: OrgContext) { setCtx(next); setDirty(true); setSavedFlash(false); }

  async function handleSave() {
    if (saving) return;
    setSaving(true);
    setError(null);
    try {
      // Always keep the local draft current so the context survives even when
      // no project is open.
      await saveContextDraft(ctx);
      if (serverUrl) {
        await postOrgContext(serverUrl, ctx);
      }
      setDirty(false);
      setSavedFlash(true);
      setTimeout(() => setSavedFlash(false), 2200);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not save. Your changes are kept locally and will sync on your next scan.");
    } finally {
      setSaving(false);
    }
  }

  const savedToProject = Boolean(serverUrl);

  return (
    <div className="profile-page">
      <div className="profile-inner oc-editor">
        <div className="profile-header-text" style={{ maxWidth: "none" }}>
          <div className="profile-name-display">Project Context</div>
          <div className="profile-subtitle" style={{ maxWidth: 520 }}>
            Tell Trojan what you are building so it can test intentionally, for security and privacy, instead of guessing from generic heuristics.
          </div>
        </div>

        <LocalPrivacyBadge />

        {savedToProject
          ? <div className="oc-target-note"><span className="oc-target-dot on" />Editing this project{projectPath ? <>: <code>{projectPath}</code></> : ""}. Saving writes <code>.trojan/context.yaml</code>.</div>
          : <div className="oc-target-note"><span className="oc-target-dot" />No project open. Changes are saved on your machine now and written into a project's <code>.trojan/context.yaml</code> the next time you scan it.</div>}

        {loadState === "loading" && <div className="oc-loading">Loading context...</div>}

        {loadState !== "loading" && (
          <>
            <div className="profile-section-group">
              <span className="profile-mono-label">WHAT ARE YOU BUILDING</span>
              <div className="profile-card"><CM /><AppSection value={ctx} onChange={update} /></div>
            </div>

            <div className="profile-section-group">
              <span className="profile-mono-label">SENSITIVE DATA</span>
              <span className="oc-group-hint">The categories of sensitive data your app handles. Trojan tests these paths harder, for privacy as well as security.</span>
              <div className="profile-card"><CM /><SensitiveSection value={ctx} onChange={update} /></div>
            </div>

            <div className="profile-section-group">
              <span className="profile-mono-label">TRUST BOUNDARIES</span>
              <span className="oc-group-hint">The zones with different levels of trust, so Trojan can reason about who can reach what.</span>
              <div className="profile-card"><CM /><BoundarySection value={ctx} onChange={update} /></div>
            </div>

            <div className="profile-section-group">
              <span className="profile-mono-label">THREAT ACTORS</span>
              <span className="oc-group-hint">Who you defend against. Trojan prioritizes the paths these actors would take.</span>
              <div className="profile-card"><CM /><ActorSection value={ctx} onChange={update} /></div>
            </div>

            {error && <div className="oc-error">{error}</div>}

            <button
              className={`profile-save-btn ${!dirty && !savedFlash ? "saved" : ""}`}
              disabled={saving || (!dirty && !savedFlash)}
              onClick={handleSave}
            >
              {saving ? "Saving..." : savedFlash ? "Saved" : dirty ? (savedToProject ? "Save to project" : "Save locally") : "Saved"}
            </button>
          </>
        )}
      </div>
    </div>
  );
}
