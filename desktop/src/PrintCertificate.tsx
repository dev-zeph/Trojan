/**
 * PrintCertificate — renders a printable security report.
 *
 * Hidden in normal UI via CSS (`display: none`).
 * Becomes the only visible element on `@media print`.
 *
 * Triggered by calling `window.print()` from the Threat Lab view.
 */

import { createPortal } from "react-dom";
import { QRCodeSVG } from "qrcode.react";

interface ScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
  scannedAt: string;
}

interface ThreatLabResult {
  threat_index: number;
  grade: "A" | "B" | "C" | "D" | "F";
  verdict: string;
  key_risks: string[];
  compliance_summary: string;
  attack_vectors: { title: string; severity: string; description: string }[];
  priority_fixes: { rank: number; title: string; description: string; type: string; command?: string }[];
}

interface PkgInfo {
  cve_count: number;
  highest_severity?: string;
  name: string;
  version: string;
}

interface PrintCertificateProps {
  projectPath: string;
  scanSummary: ScanSummary | null;
  threatLabResult: ThreatLabResult | null;
  packages: PkgInfo[];
  userLevel?: string;   // "founder" | "developer" | undefined
}

const GRADE_COLOR: Record<string, string> = {
  A: "#16a34a", B: "#65a30d", C: "#d97706", D: "#ea580c", F: "#dc2626",
};

const SEV_COLOR: Record<string, string> = {
  critical: "#dc2626", high: "#ea580c", medium: "#a16207", low: "#1d4ed8", info: "#4b5563",
};

export function PrintCertificate({
  projectPath,
  scanSummary,
  threatLabResult,
  packages,
}: PrintCertificateProps) {
  const projectName = projectPath.split("/").pop() || projectPath || "Unknown Project";
  const scanDate    = scanSummary
    ? new Date(scanSummary.scannedAt).toLocaleDateString("en-US", {
        year: "numeric", month: "long", day: "numeric",
        hour: "2-digit", minute: "2-digit",
      })
    : new Date().toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });

  const vulnPkgs     = packages.filter(p => p.cve_count > 0).length;
  const grade        = threatLabResult?.grade;
  const gradeColor   = grade ? (GRADE_COLOR[grade] ?? "#6b7280") : "#6b7280";
  const threatIndex  = threatLabResult?.threat_index;

  // Unique (non-cryptographic) report ID from path + date
  const reportId = btoa(`${projectPath}-${scanSummary?.scannedAt ?? Date.now()}`)
    .replace(/[^a-z0-9]/gi, "")
    .slice(0, 16)
    .toUpperCase();

  return createPortal(
    <div id="print-certificate" className="cert-root">
      {/* ── Header ── */}
      <div className="cert-header">
        <div className="cert-logo-row">
          <img src="/logo.png" alt="Trojan" className="cert-logo" />
          <div>
            <div className="cert-brand">TROJAN</div>
            <div className="cert-doc-type">Security Assessment Report</div>
          </div>
        </div>
        <div className="cert-meta">
          <div className="cert-meta-row">
            <span className="cert-label">Project</span>
            <span className="cert-value">{projectName}</span>
          </div>
          <div className="cert-meta-row">
            <span className="cert-label">Path</span>
            <span className="cert-value cert-path">{projectPath}</span>
          </div>
          <div className="cert-meta-row">
            <span className="cert-label">Scanned</span>
            <span className="cert-value">{scanDate}</span>
          </div>
          <div className="cert-meta-row">
            <span className="cert-label">Report ID</span>
            <span className="cert-value cert-mono">{reportId}</span>
          </div>
        </div>
      </div>

      <div className="cert-divider" />

      {/* ── Grade + Index ── */}
      {threatLabResult ? (
        <div className="cert-grade-row">
          <div className="cert-grade-box">
            <div className="cert-grade-letter" style={{ color: gradeColor }}>{grade}</div>
            <div className="cert-grade-label">Security Grade</div>
          </div>
          <div className="cert-index-box">
            <div className="cert-index-num" style={{ color: gradeColor }}>{threatIndex}</div>
            <div className="cert-grade-label">Threat Index (0 = secure)</div>
          </div>
          <div className="cert-verdict-box">
            <div className="cert-section-title">Executive Summary</div>
            <p className="cert-verdict-text">{threatLabResult.verdict}</p>
          </div>
        </div>
      ) : (
        <div className="cert-no-threatlab">
          <em>Run Threat Lab to include AI-powered grade and executive summary in this report.</em>
        </div>
      )}

      <div className="cert-divider" />

      {/* ── Findings ── */}
      <div className="cert-two-col">
        <div>
          <div className="cert-section-title">Findings Summary</div>
          {scanSummary ? (
            <table className="cert-table">
              <thead>
                <tr>
                  <th>Severity</th><th>Count</th>
                </tr>
              </thead>
              <tbody>
                {(["critical","high","medium","low","info"] as const).map(sev => (
                  scanSummary[sev] > 0 && (
                    <tr key={sev}>
                      <td>
                        <span className="cert-sev-dot" style={{ background: SEV_COLOR[sev] }} />
                        {sev.charAt(0).toUpperCase() + sev.slice(1)}
                      </td>
                      <td><strong>{scanSummary[sev]}</strong></td>
                    </tr>
                  )
                ))}
                <tr className="cert-table-total">
                  <td>Total findings</td>
                  <td><strong>{scanSummary.total}</strong></td>
                </tr>
              </tbody>
            </table>
          ) : (
            <p className="cert-muted">No scan data available.</p>
          )}
        </div>

        <div>
          <div className="cert-section-title">Dependency Health</div>
          <table className="cert-table">
            <tbody>
              <tr>
                <td>Total packages scanned</td>
                <td><strong>{packages.length}</strong></td>
              </tr>
              <tr>
                <td>Packages with CVEs</td>
                <td><strong style={{ color: vulnPkgs > 0 ? SEV_COLOR.high : SEV_COLOR.info }}>{vulnPkgs}</strong></td>
              </tr>
              <tr>
                <td>Clean packages</td>
                <td><strong>{packages.length - vulnPkgs}</strong></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Key Risks ── */}
      {threatLabResult?.key_risks && threatLabResult.key_risks.length > 0 && (
        <>
          <div className="cert-divider" />
          <div className="cert-section-title">Key Risks</div>
          <ul className="cert-risk-list">
            {threatLabResult.key_risks.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        </>
      )}

      {/* ── Attack Vectors ── */}
      {threatLabResult?.attack_vectors && threatLabResult.attack_vectors.length > 0 && (
        <>
          <div className="cert-divider" />
          <div className="cert-section-title">Attack Vectors Identified</div>
          <table className="cert-table cert-table-full">
            <thead>
              <tr><th>Vector</th><th>Severity</th><th>Exploitability</th></tr>
            </thead>
            <tbody>
              {threatLabResult.attack_vectors.map((v, i) => (
                <tr key={i}>
                  <td>{v.title}</td>
                  <td>
                    <span className="cert-sev-dot" style={{ background: SEV_COLOR[v.severity] ?? "#6b7280" }} />
                    {v.severity}
                  </td>
                  <td>{(v as { exploitability?: string }).exploitability ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {/* ── Priority Fixes ── */}
      {threatLabResult?.priority_fixes && threatLabResult.priority_fixes.length > 0 && (
        <>
          <div className="cert-divider" />
          <div className="cert-section-title">Recommended Remediation (Top {Math.min(5, threatLabResult.priority_fixes.length)})</div>
          <ol className="cert-fix-list">
            {threatLabResult.priority_fixes.slice(0, 5).map((fix) => (
              <li key={fix.rank}>
                <strong>{fix.title}</strong> — {fix.description}
                {fix.command && (
                  <div className="cert-code">{fix.command}</div>
                )}
              </li>
            ))}
          </ol>
        </>
      )}

      {/* ── Compliance ── */}
      {threatLabResult?.compliance_summary && (
        <>
          <div className="cert-divider" />
          <div className="cert-section-title">Compliance Coverage</div>
          <p className="cert-compliance-text">{threatLabResult.compliance_summary}</p>
        </>
      )}

      {/* ── Footer ── */}
      <div className="cert-divider" />
      <div className="cert-footer">
        <div className="cert-footer-left">
          <div className="cert-footer-brand">Generated by Trojan Security</div>
          <div className="cert-footer-url">trojancli.com</div>
          <div className="cert-footer-disclaimer">
            This report reflects the state of the codebase at the time of scan. Security posture
            may change as code evolves. Re-scan regularly to maintain an up-to-date assessment.
          </div>
        </div>
        <div className="cert-footer-qr">
          <QRCodeSVG
            value="https://trojancli.com"
            size={72}
            fgColor="#0a0a0a"
            bgColor="#ffffff"
            level="M"
          />
          <div className="cert-qr-label">trojancli.com</div>
        </div>
      </div>
    </div>,
    document.body
  );
}
