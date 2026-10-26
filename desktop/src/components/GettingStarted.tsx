import { useEffect, useState } from "react";
import type { CodeAuthor, DashboardMode, SecurityExperience } from "../types";

// ── Getting Started ───────────────────────────────────────────────────────
// The very first screen. Two questions about the founder decide which
// dashboard they get (simple or full) and how plain the AI explanations are.
// Both can be changed later from Profile.

export type FounderAnswers = {
  securityExperience: SecurityExperience;
  codeAuthor: CodeAuthor;
  dashboard: DashboardMode;
  familiarity: number;
  aboutYou: string;
};

const EXPERIENCE: { value: SecurityExperience; title: string; desc: string }[] = [
  { value: "none",        title: "None yet",        desc: "I'm building my product and want to know it's safe." },
  { value: "some",        title: "A little",        desc: "I know the basics, like keeping passwords and keys private." },
  { value: "comfortable", title: "I'm comfortable", desc: "Terms like XSS, CVEs and penetration testing are familiar." },
];

const AUTHORS: { value: CodeAuthor; title: string; desc: string; about: string }[] = [
  { value: "ai-builder", title: "An AI app builder",  desc: "Lovable, Bolt, Replit, v0",               about: "I build my product with an AI app builder (Lovable, Bolt, Replit or similar)." },
  { value: "ai-editor",  title: "An AI coding tool",  desc: "Cursor, Claude Code, Windsurf, Codex",    about: "I build my product with an AI coding tool (Cursor, Claude Code or similar)." },
  { value: "me",         title: "I write it myself",  desc: "With or without AI help",                 about: "I write most of my product's code myself." },
  { value: "team",       title: "My team does",       desc: "Developers I work with",                  about: "A team of developers writes my product's code." },
];

// Experience decides the dashboard: anyone not already comfortable with
// security language starts on the simple one.
export function answersFor(exp: SecurityExperience, author: CodeAuthor): FounderAnswers {
  return {
    securityExperience: exp,
    codeAuthor: author,
    dashboard: exp === "comfortable" ? "full" : "simple",
    familiarity: exp === "none" ? 0 : exp === "some" ? 1 : 2,
    aboutYou: AUTHORS.find((a) => a.value === author)?.about ?? "",
  };
}

type Step = "intro" | "experience" | "author" | "setup";
const ORDER: Step[] = ["intro", "experience", "author", "setup"];

export function GettingStarted({ onDone }: { onDone: (a: FounderAnswers) => void }) {
  const [step, setStep]       = useState<Step>("intro");
  const [exp, setExp]         = useState<SecurityExperience | null>(null);
  const [author, setAuthor]   = useState<CodeAuthor | null>(null);
  const [dir, setDir]         = useState<"fwd" | "back">("fwd");

  function go(next: Step, d: "fwd" | "back" = "fwd") {
    setDir(d);
    setStep(next);
  }

  // A short pause after a pick so the selection registers before moving on.
  function pickExperience(v: SecurityExperience) {
    setExp(v);
    window.setTimeout(() => go("author"), 260);
  }
  function pickAuthor(v: CodeAuthor) {
    setAuthor(v);
    window.setTimeout(() => go("setup"), 260);
  }

  const answers = exp && author ? answersFor(exp, author) : null;
  const progress = ORDER.indexOf(step) / (ORDER.length - 1);

  return (
    <div className="gs-stage">
      <div className="gs-grid-bg" />
      <JourneyLine />
      <div className="gs-progress"><div className="gs-progress-fill" style={{ width: `${progress * 100}%` }} /></div>

      <div className="gs-top">
        <img src="/logo.png" alt="Trojan" className="gs-logo" />
        <span className="gs-eyebrow">GETTING STARTED</span>
      </div>

      <div key={step} className={`gs-panel gs-enter-${dir}`}>
        {step === "intro" && (
          <>
            <h1 className="gs-title">Firstly, we want to get an overview of you</h1>
            <p className="gs-sub">
              This tells us what to show you and how to work with you. It's two quick questions, and you can change your answers later in your profile.
            </p>
            <button className="gs-cta" onClick={() => go("experience")} autoFocus>Let's begin {"→"}</button>
          </>
        )}

        {step === "experience" && (
          <>
            <span className="gs-count">1 of 2</span>
            <h1 className="gs-title">What's your experience with cybersecurity?</h1>
            <div className="gs-options">
              {EXPERIENCE.map((o, i) => (
                <button
                  key={o.value}
                  className={`gs-option ${exp === o.value ? "on" : ""}`}
                  style={{ animationDelay: `${80 + i * 60}ms` }}
                  onClick={() => pickExperience(o.value)}
                >
                  <span className="gs-option-title">{o.title}</span>
                  <span className="gs-option-desc">{o.desc}</span>
                </button>
              ))}
            </div>
            <button className="gs-back" onClick={() => go("intro", "back")}>{"←"} Back</button>
          </>
        )}

        {step === "author" && (
          <>
            <span className="gs-count">2 of 2</span>
            <h1 className="gs-title">Who writes your code?</h1>
            <div className="gs-options gs-options-2">
              {AUTHORS.map((o, i) => (
                <button
                  key={o.value}
                  className={`gs-option ${author === o.value ? "on" : ""}`}
                  style={{ animationDelay: `${80 + i * 60}ms` }}
                  onClick={() => pickAuthor(o.value)}
                >
                  <span className="gs-option-title">{o.title}</span>
                  <span className="gs-option-desc">{o.desc}</span>
                </button>
              ))}
            </div>
            <button className="gs-back" onClick={() => go("experience", "back")}>{"←"} Back</button>
          </>
        )}

        {step === "setup" && answers && <SettingUp answers={answers} onDone={() => onDone(answers)} />}
      </div>
    </div>
  );
}

// The hand-off moment: a short checklist that ticks through what the answers
// changed, then moves on to sign-in by itself.
function SettingUp({ answers, onDone }: { answers: FounderAnswers; onDone: () => void }) {
  const simple = answers.dashboard === "simple";
  const lines = [
    simple ? "Choosing a simple dashboard" : "Choosing the full dashboard",
    simple ? "Keeping explanations in plain language" : "Turning on full technical detail",
    answers.codeAuthor === "team" || answers.codeAuthor === "me" ? "Preparing your project scans" : "Getting ready to work with your AI tool",
  ];
  const [done, setDone] = useState(0);

  useEffect(() => {
    if (done < lines.length) {
      const t = window.setTimeout(() => setDone((d) => d + 1), 650);
      return () => window.clearTimeout(t);
    }
    const t = window.setTimeout(onDone, 700);
    return () => window.clearTimeout(t);
  }, [done, lines.length, onDone]);

  return (
    <>
      <h1 className="gs-title">{done < lines.length ? "Setting up your workspace" : "You're all set"}</h1>
      <ul className="gs-checklist">
        {lines.map((l, i) => (
          <li key={l} className={i < done ? "done" : i === done ? "active" : ""}>
            <span className="gs-check">
              {i < done
                ? <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><path d="M20 6 9 17l-5-5" /></svg>
                : <span className="gs-spinner" />}
            </span>
            {l}
          </li>
        ))}
      </ul>
    </>
  );
}

// Background flourish: a line that sets off from the left edge, twirls once
// and runs out the right edge, then a small dot keeps travelling along it.
const JOURNEY_PATH =
  "M-20,210 C160,210 300,150 450,175 C560,193 640,255 600,285 C560,315 480,275 505,222 " +
  "C530,170 650,150 760,172 C900,200 1040,130 1220,150";

function JourneyLine() {
  return (
    <svg className="gs-journey" viewBox="0 0 1200 320" preserveAspectRatio="none" aria-hidden="true">
      <path className="gs-journey-path" d={JOURNEY_PATH} pathLength={1} />
      <circle className="gs-journey-dot" r="4">
        <animateMotion dur="7s" begin="2.6s" repeatCount="indefinite" path={JOURNEY_PATH} />
      </circle>
    </svg>
  );
}
