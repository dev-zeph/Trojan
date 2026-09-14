// Trojan Token balance chip.
//
// "Tokens" here are the BILLING unit the customer buys and spends -- never LLM
// tokens. The two must never appear together in one line of UI copy, or the
// screen ends up saying things like "this run used 163,000 tokens and cost you
// 365 tokens". Anything that shows LLM counts calls them "context" instead.

interface Props {
  balance: number | null;
  /** Below this, the chip warns. Roughly one Sonnet pen-test. */
  lowThreshold?: number;
  onTopUp: () => void;
  compact?: boolean;
}

export function TokenBalance({ balance, lowThreshold = 400, onTopUp, compact }: Props) {
  // null = not loaded yet. Render a neutral placeholder rather than "0", which
  // would read as "you are out" and is the one wrong answer here.
  const loading = balance === null;
  const empty = !loading && balance <= 0;
  const low = !loading && !empty && balance < lowThreshold;

  const color = empty ? "#f87171" : low ? "#fbbf24" : "#a3a3a3";
  const border = empty
    ? "rgba(248,113,113,0.4)"
    : low
      ? "rgba(251,191,36,0.4)"
      : "rgba(255,255,255,0.12)";

  return (
    <button
      onClick={onTopUp}
      title={
        loading ? "Checking your token balance"
        : empty ? "You are out of Trojan Tokens — click to top up"
        : low ? `${balance.toLocaleString()} Trojan Tokens left — click to top up`
        : `${balance.toLocaleString()} Trojan Tokens — click to top up`
      }
      style={{
        display: "flex", alignItems: "center", gap: 6,
        width: "100%", padding: compact ? "4px 8px" : "6px 10px",
        background: "transparent", border: `1px solid ${border}`,
        color, cursor: "pointer", font: "500 11px Inter, sans-serif",
        letterSpacing: "0.2px",
      }}
    >
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
        <circle cx="12" cy="12" r="9" />
        <path d="M12 7v10M9.5 9.5h5M9.5 14.5h5" strokeLinecap="round" />
      </svg>
      <span style={{ flex: 1, textAlign: "left" }}>
        {loading ? "—" : balance.toLocaleString()}
      </span>
      <span style={{ opacity: 0.65, fontSize: 10 }}>
        {empty ? "TOP UP" : "TOKENS"}
      </span>
    </button>
  );
}

/**
 * Cost guidance for the pen-test setup screen.
 *
 * Shows a RANGE, not a point estimate. A run's cost depends on how many steps
 * the agent takes, how large the crawled surface is, and which model is driving
 * it -- so a single number would be wrong most of the time and would read as a
 * promise. The figures come from measured runs (docs/agentic-dast.md) and
 * should be replaced with the p75 out of usage_events once that has history.
 */
export function RunCostHint({ balance, model }: { balance: number | null; model: "sonnet" | "opus" }) {
  const typical = model === "opus" ? 915 : 365;
  const range = model === "opus" ? "250–950" : "100–400";
  const affordable = balance !== null && balance >= typical;

  return (
    <div style={{
      display: "flex", flexDirection: "column", gap: 4,
      padding: "10px 12px", border: "1px solid rgba(255,255,255,0.1)",
      font: "400 11px Inter, sans-serif", color: "#a3a3a3",
    }}>
      <div style={{ display: "flex", justifyContent: "space-between" }}>
        <span>Typical cost</span>
        <span style={{ color: "#e5e5e5" }}>{range} tokens</span>
      </div>
      <div style={{ opacity: 0.7, lineHeight: 1.5 }}>
        Charged per step as the agent works, not upfront. If you run out
        mid-engagement the run pauses and can be resumed after a top-up —
        nothing is lost.
      </div>
      {balance !== null && !affordable && (
        <div style={{ color: "#fbbf24", marginTop: 2 }}>
          Your balance may not cover a full run. It will pause rather than fail.
        </div>
      )}
    </div>
  );
}
