import { useEffect, useMemo, useState } from "react";

// AttackMarket is the §9.4 attack-template shop. It follows the compass Area-4
// reference: a card-grid browse (title, technique badges, official badge, stars,
// use count) → a detail view leading with the breach STORY (transparency) and a
// prominent, non-collapsible "what the agent will attempt" disclosure (the
// generalized playbook), with a primary "Use this template" CTA and an honest
// "review before you run" framing. Templates are first-party/curated, so the
// verified badge reads "Trojan official" and there's no community-upload surface.

const SUPABASE_URL = "https://dtmocojzvgsswjdsrmqr.supabase.co";
const ENDPOINT = `${SUPABASE_URL}/functions/v1/attack-templates`;

export interface AttackTemplate {
  slug: string;
  title: string;
  technique: string[];
  min_tier: "passive" | "safe-active" | "aggressive";
  breach_story: string;
  prompt_body: string;
  use_count: number;
  star_count: number;
  starred?: boolean;
}

interface Props {
  getToken: () => Promise<string>;
  selectedSlug?: string;
  onUseTemplate: (t: AttackTemplate) => void;
}

export function AttackMarket({ getToken, selectedSlug, onUseTemplate }: Props) {
  const [templates, setTemplates] = useState<AttackTemplate[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [technique, setTechnique] = useState("");
  const [openSlug, setOpenSlug] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const token = await getToken();
        const res = await fetch(ENDPOINT, { headers: { Authorization: `Bearer ${token}` } });
        if (!res.ok) throw new Error(res.status === 403 ? "Attack Market is a Pro feature." : `Failed to load (${res.status})`);
        const data = await res.json();
        if (!cancelled) setTemplates(data.templates ?? []);
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : "Could not load the Attack Market.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [getToken]);

  const techniques = useMemo(() => {
    const s = new Set<string>();
    templates.forEach((t) => t.technique.forEach((x) => s.add(x)));
    return Array.from(s).sort();
  }, [templates]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return templates.filter((t) => {
      if (technique && !t.technique.includes(technique)) return false;
      if (!q) return true;
      return t.title.toLowerCase().includes(q) || t.breach_story.toLowerCase().includes(q);
    });
  }, [templates, query, technique]);

  async function toggleStar(t: AttackTemplate) {
    const next = !t.starred;
    // Optimistic update.
    setTemplates((rows) => rows.map((r) => r.slug === t.slug
      ? { ...r, starred: next, star_count: Math.max(0, r.star_count + (next ? 1 : -1)) }
      : r));
    try {
      const token = await getToken();
      await fetch(ENDPOINT, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ slug: t.slug, star: next }),
      });
    } catch {
      // Revert on failure.
      setTemplates((rows) => rows.map((r) => r.slug === t.slug
        ? { ...r, starred: !next, star_count: Math.max(0, r.star_count + (next ? -1 : 1)) }
        : r));
    }
  }

  const open = openSlug ? templates.find((t) => t.slug === openSlug) ?? null : null;

  if (loading) return <div className="am-state">Loading the Attack Market…</div>;
  if (error) return <div className="am-state am-state--error">{error}</div>;

  if (open) {
    return (
      <AttackDetail
        t={open}
        isSelected={open.slug === selectedSlug}
        onBack={() => setOpenSlug(null)}
        onStar={() => toggleStar(open)}
        onUse={() => onUseTemplate(open)}
      />
    );
  }

  return (
    <div className="am-wrap">
      <div className="am-head">
        <h1 className="am-title">Attack Market</h1>
        <p className="am-sub">Curated playbooks drawn from real breaches. Pick one and the agent replays the pattern against your app, within your rules of engagement.</p>
      </div>

      <div className="am-controls">
        <input className="am-search" placeholder="Search breaches…" value={query} onChange={(e) => setQuery(e.target.value)} />
        <div className="am-chips">
          <button className={`am-chip ${technique === "" ? "active" : ""}`} onClick={() => setTechnique("")}>All</button>
          {techniques.map((tech) => (
            <button key={tech} className={`am-chip ${technique === tech ? "active" : ""}`} onClick={() => setTechnique(technique === tech ? "" : tech)}>{tech}</button>
          ))}
        </div>
      </div>

      {filtered.length === 0 ? (
        <div className="am-state">No templates match.</div>
      ) : (
        <div className="am-grid">
          {filtered.map((t) => (
            <AttackCard
              key={t.slug} t={t}
              isSelected={t.slug === selectedSlug}
              onOpen={() => setOpenSlug(t.slug)}
              onStar={() => toggleStar(t)}
              onUse={() => onUseTemplate(t)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function OfficialBadge() {
  return (
    <span className="am-official" title="Authored and verified by Trojan">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 6 9 17l-5-5" /></svg>
      Trojan official
    </span>
  );
}

function StarButton({ starred, count, onClick }: { starred?: boolean; count: number; onClick: () => void }) {
  return (
    <button className={`am-star ${starred ? "active" : ""}`} onClick={(e) => { e.stopPropagation(); onClick(); }} title={starred ? "Unstar" : "Star"}>
      <svg width="13" height="13" viewBox="0 0 24 24" fill={starred ? "currentColor" : "none"} stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z" /></svg>
      {count}
    </button>
  );
}

function TechBadges({ list }: { list: string[] }) {
  return <div className="am-techs">{list.map((x) => <span key={x} className="am-tech">{x}</span>)}</div>;
}

function AttackCard({ t, isSelected, onOpen, onStar, onUse }: { t: AttackTemplate; isSelected: boolean; onOpen: () => void; onStar: () => void; onUse: () => void }) {
  return (
    <div className={`am-card ${isSelected ? "selected" : ""}`} onClick={onOpen} role="button" tabIndex={0}>
      <div className="am-card-top">
        <OfficialBadge />
        <StarButton starred={t.starred} count={t.star_count} onClick={onStar} />
      </div>
      <h3 className="am-card-title">{t.title}</h3>
      <p className="am-card-story">{t.breach_story}</p>
      <TechBadges list={t.technique} />
      <div className="am-card-foot">
        <span className="am-usecount">{t.use_count} run{t.use_count === 1 ? "" : "s"}</span>
        <button className="am-use" onClick={(e) => { e.stopPropagation(); onUse(); }}>
          {isSelected ? "Selected ✓" : "Use this template"}
        </button>
      </div>
    </div>
  );
}

function AttackDetail({ t, isSelected, onBack, onStar, onUse }: { t: AttackTemplate; isSelected: boolean; onBack: () => void; onStar: () => void; onUse: () => void }) {
  // Present the generalized playbook as human-legible steps for the disclosure.
  const steps = t.prompt_body.split("\n").map((l) => l.trim()).filter(Boolean);
  return (
    <div className="am-detail">
      <button className="am-back" onClick={onBack}>← Back to market</button>
      <div className="am-detail-head">
        <div>
          <div className="am-detail-badges"><OfficialBadge /><span className="am-tier">works best at: {t.min_tier}</span></div>
          <h1 className="am-detail-title">{t.title}</h1>
          <TechBadges list={t.technique} />
        </div>
        <div className="am-detail-actions">
          <StarButton starred={t.starred} count={t.star_count} onClick={onStar} />
          <button className="am-use am-use--lg" onClick={onUse}>{isSelected ? "Selected ✓" : "Use this template"}</button>
        </div>
      </div>

      <section className="am-section">
        <h2 className="am-section-h">How this breach happened</h2>
        <p className="am-story">{t.breach_story}</p>
      </section>

      {/* Transparency disclosure — non-collapsible, the category-appropriate trust
          surface: exactly what the agent will attempt on your app. */}
      <section className="am-section am-disclosure">
        <h2 className="am-section-h">What the agent will attempt</h2>
        <p className="am-disclosure-note">This runs against your own app, within your rules of engagement. Read it before you run it.</p>
        <ol className="am-steps">{steps.map((s, i) => <li key={i}>{s.replace(/^\d+\.\s*/, "")}</li>)}</ol>
      </section>
    </div>
  );
}
