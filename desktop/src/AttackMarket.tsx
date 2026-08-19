import { useEffect, useMemo, useState } from "react";

// AttackMarket is the §9.4 attack-template shop, styled after the VS Code
// Marketplace: a browse grid of extension-style cards → a detail page with an
// icon + title + publisher line (verified check, use count, rating), tabbed
// content, and a right-rail info/trust panel. Templates are first-party/curated,
// so the "publisher" is always Trojan (verified) and there's no upload surface.

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

// deterministic accent hue from the slug, so each template's icon is stable + distinct.
function hue(slug: string): number {
  let h = 0;
  for (let i = 0; i < slug.length; i++) h = (h * 31 + slug.charCodeAt(i)) % 360;
  return h;
}

function tagline(t: AttackTemplate): string {
  const first = t.breach_story.split(/(?<=\.)\s/)[0] ?? t.breach_story;
  return first.length > 140 ? first.slice(0, 140) + "…" : first;
}

function TemplateIcon({ slug, size = 96 }: { slug: string; size?: number }) {
  const h = hue(slug);
  return (
    <div className="am-icon" style={{ width: size, height: size, background: `linear-gradient(145deg, hsl(${h} 55% 42%), hsl(${(h + 40) % 360} 60% 32%))` }}>
      <svg width={size * 0.5} height={size * 0.5} viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="9" /><path d="M12 3v4 M12 17v4 M3 12h4 M17 12h4" /><circle cx="12" cy="12" r="2.5" fill="white" stroke="none" />
      </svg>
    </div>
  );
}

function VerifiedCheck() {
  return (
    <svg className="am-verified" width="13" height="13" viewBox="0 0 24 24" fill="currentColor" aria-label="Verified publisher">
      <path d="M12 1l2.4 2.1 3.2-.3 1.3 2.9 2.9 1.3-.3 3.2L23.5 16l-2.1 2.4.3 3.2-2.9 1.3-1.3 2.9-3.2-.3L12 23.5 9.6 21.4l-3.2.3-1.3-2.9-2.9-1.3.3-3.2L.5 12l2.1-2.4-.3-3.2 2.9-1.3L6.4 2.2l3.2.3z" opacity=".25" />
      <path d="M10.6 14.6l-2.2-2.2-1.2 1.2 3.4 3.4 6-6-1.2-1.2z" fill="#fff" />
    </svg>
  );
}

function Rating({ count }: { count: number }) {
  return (
    <span className="am-rating" title={`${count} star${count === 1 ? "" : "s"}`}>
      <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01z" /></svg>
      {count}
    </span>
  );
}

function UseCount({ count }: { count: number }) {
  return (
    <span className="am-dl" title={`${count} runs`}>
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4 M7 10l5 5 5-5 M12 15V3" /></svg>
      {count}
    </span>
  );
}

function TechBadges({ list }: { list: string[] }) {
  return <div className="am-techs">{list.map((x) => <span key={x} className="am-tech">{x}</span>)}</div>;
}

function StarButton({ starred, onClick, label }: { starred?: boolean; onClick: () => void; label?: boolean }) {
  return (
    <button className={`am-starbtn ${starred ? "active" : ""}`} onClick={(e) => { e.stopPropagation(); onClick(); }}>
      <svg width="14" height="14" viewBox="0 0 24 24" fill={starred ? "currentColor" : "none"} stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01z" /></svg>
      {label ? (starred ? "Starred" : "Star") : null}
    </button>
  );
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
    setTemplates((rows) => rows.map((r) => r.slug === t.slug
      ? { ...r, starred: next, star_count: Math.max(0, r.star_count + (next ? 1 : -1)) } : r));
    try {
      const token = await getToken();
      await fetch(ENDPOINT, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ slug: t.slug, star: next }),
      });
    } catch {
      setTemplates((rows) => rows.map((r) => r.slug === t.slug
        ? { ...r, starred: !next, star_count: Math.max(0, r.star_count + (next ? -1 : 1)) } : r));
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
            <div key={t.slug} className={`am-card ${t.slug === selectedSlug ? "selected" : ""}`} onClick={() => setOpenSlug(t.slug)} role="button" tabIndex={0}>
              <TemplateIcon slug={t.slug} size={52} />
              <div className="am-card-body">
                <div className="am-card-titlerow">
                  <h3 className="am-card-title">{t.title}</h3>
                  <StarButton starred={t.starred} onClick={() => toggleStar(t)} />
                </div>
                <div className="am-publisher am-publisher--sm">Trojan<VerifiedCheck /></div>
                <p className="am-card-story">{tagline(t)}</p>
                <div className="am-card-meta">
                  <UseCount count={t.use_count} />
                  <Rating count={t.star_count} />
                  <span className="am-tech am-tech--tier">{t.min_tier}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function AttackDetail({ t, isSelected, onBack, onStar, onUse }: { t: AttackTemplate; isSelected: boolean; onBack: () => void; onStar: () => void; onUse: () => void }) {
  const [tab, setTab] = useState<"story" | "playbook">("story");
  const steps = t.prompt_body.split("\n").map((l) => l.trim()).filter(Boolean).map((s) => s.replace(/^\d+\.\s*/, ""));

  return (
    <div className="am-detail">
      <button className="am-back" onClick={onBack}>← Marketplace</button>

      {/* Header — icon + title + publisher line + actions (VS Code layout) */}
      <div className="am-dhead">
        <TemplateIcon slug={t.slug} size={104} />
        <div className="am-dhead-main">
          <h1 className="am-dtitle">{t.title}</h1>
          <div className="am-publisher">
            <span className="am-pubname">Trojan<VerifiedCheck /></span>
            <a className="am-publink" href="https://trojancli.com" target="_blank" rel="noreferrer">trojancli.com</a>
            <span className="am-sep">|</span>
            <UseCount count={t.use_count} />
            <span className="am-sep">|</span>
            <Rating count={t.star_count} />
          </div>
          <p className="am-dtag">{tagline(t)}</p>
          <div className="am-dactions">
            <button className="am-use am-use--lg" onClick={onUse}>{isSelected ? "Selected ✓" : "Use this template"}</button>
            <StarButton starred={t.starred} onClick={onStar} label />
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="am-tabs">
        <button className={`am-tab ${tab === "story" ? "active" : ""}`} onClick={() => setTab("story")}>How it happened</button>
        <button className={`am-tab ${tab === "playbook" ? "active" : ""}`} onClick={() => setTab("playbook")}>What the agent attempts</button>
      </div>

      {/* Two-column body */}
      <div className="am-dbody">
        <div className="am-dcontent">
          {tab === "story" ? (
            <p className="am-story">{t.breach_story}</p>
          ) : (
            <>
              <p className="am-disclosure-note">This runs against your own app, within your rules of engagement — the safety envelope overrides anything here. Read it before you run it.</p>
              <ol className="am-steps">{steps.map((s, i) => <li key={i}>{s}</li>)}</ol>
            </>
          )}
        </div>

        <aside className="am-rail">
          <div className="am-panel">
            <div className="am-panel-h">Details</div>
            <Row label="Techniques"><TechBadges list={t.technique} /></Row>
            <Row label="Best at tier"><span className="am-mono">{t.min_tier}</span></Row>
            <Row label="Community stars"><span className="am-mono">{t.star_count}</span></Row>
            <Row label="Times run"><span className="am-mono">{t.use_count}</span></Row>
            <Row label="Template id"><span className="am-mono am-mono--wrap">{t.slug}</span></Row>
          </div>
          <div className="am-panel">
            <div className="am-panel-h">Trust</div>
            <TrustLine>First-party — authored &amp; verified by Trojan</TrustLine>
            <TrustLine>Runs within your rules of engagement</TrustLine>
            <TrustLine>Report-only — non-destructive, single-proof</TrustLine>
          </div>
        </aside>
      </div>
    </div>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="am-row">
      <span className="am-row-label">{label}</span>
      <span className="am-row-val">{children}</span>
    </div>
  );
}

function TrustLine({ children }: { children: React.ReactNode }) {
  return (
    <div className="am-trust">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 6 9 17l-5-5" /></svg>
      <span>{children}</span>
    </div>
  );
}
