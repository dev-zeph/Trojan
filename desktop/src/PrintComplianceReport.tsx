/**
 * PrintComplianceReport — renders a printable compliance report.
 *
 * Hidden in normal UI via CSS (`display: none`).
 * Becomes the only visible element on `@media print` when present.
 *
 * Triggered by calling `window.print()` from the Compliance Lab view.
 */

import { createPortal } from "react-dom";
import { QRCodeSVG } from "qrcode.react";

interface ComplianceLabResult {
  grade: "A" | "B" | "C" | "D" | "F";
  score: number;
  executive_summary: string;
  license_verdict: string;
  privacy_verdict: string;
  recommendations: string[];
}

interface PkgInfo {
  name: string;
  version: string;
  license?: string;
  license_risk?: string;
}

interface PrintComplianceReportProps {
  projectPath: string;
  result: ComplianceLabResult | null;
  packages: PkgInfo[];
}

const GRADE_COLOR: Record<string, string> = {
  A: "#16a34a", B: "#65a30d", C: "#ca8a04", D: "#ea580c", F: "#dc2626",
};

export function PrintComplianceReport({ projectPath, result, packages }: PrintComplianceReportProps) {
  if (!result) return null;

  const projectName = projectPath.split("/").pop() || projectPath || "Unknown Project";
  const scanDate = new Date().toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric", hour: "2-digit", minute: "2-digit" });
  const gradeColor = GRADE_COLOR[result.grade] ?? "#6b7280";

  const copyleft = packages.filter(p => p.license_risk === "copyleft");
  const weakCopyleft = packages.filter(p => p.license_risk === "weak-copyleft");
  const unknown = packages.filter(p => p.license_risk === "unknown" || !p.license_risk);
  const permissive = packages.filter(p => p.license_risk === "permissive");

  const reportId = btoa(`${projectPath}-compliance-${Date.now()}`)
    .replace(/[^a-z0-9]/gi, "")
    .slice(0, 16)
    .toUpperCase();

  return createPortal(
    <div id="print-compliance-report" className="cert-root">
      {/* Header */}
      <div className="cert-header">
        <div className="cert-logo-row">
          <img src="/logo.png" alt="Trojan" className="cert-logo" />
          <div>
            <div className="cert-brand">TROJAN</div>
            <div className="cert-doc-type">Compliance Report</div>
          </div>
        </div>
        <div className="cert-meta">
          <div className="cert-meta-row">
            <span className="cert-label">Project</span>
            <span className="cert-value">{projectName}</span>
          </div>
          <div className="cert-meta-row">
            <span className="cert-label">Generated</span>
            <span className="cert-value">{scanDate}</span>
          </div>
          <div className="cert-meta-row">
            <span className="cert-label">Report ID</span>
            <span className="cert-value cert-mono">{reportId}</span>
          </div>
        </div>
      </div>

      <div className="cert-divider" />

      {/* Grade + Summary */}
      <div className="cert-grade-row">
        <div className="cert-grade-box">
          <div className="cert-grade-letter" style={{ color: gradeColor }}>{result.grade}</div>
          <div className="cert-grade-label">Compliance Grade</div>
        </div>
        <div className="cert-index-box">
          <div className="cert-index-num" style={{ color: gradeColor }}>{result.score}</div>
          <div className="cert-grade-label">Score (0–100)</div>
        </div>
        <div className="cert-verdict-box">
          <div className="cert-section-title">Executive Summary</div>
          <p className="cert-verdict-text">{result.executive_summary}</p>
        </div>
      </div>

      <div className="cert-divider" />

      {/* License Assessment */}
      <div className="cert-section-title">License Assessment</div>
      <p className="cert-verdict-text" style={{ marginBottom: 12 }}>{result.license_verdict}</p>

      <div className="cert-two-col">
        <div>
          <table className="cert-table">
            <thead><tr><th>Category</th><th>Count</th></tr></thead>
            <tbody>
              <tr><td>Permissive (MIT, BSD, Apache)</td><td><strong>{permissive.length}</strong></td></tr>
              <tr><td>Weak Copyleft (LGPL, MPL)</td><td><strong>{weakCopyleft.length}</strong></td></tr>
              <tr><td style={{ color: copyleft.length > 0 ? "#dc2626" : "inherit" }}>Copyleft (GPL, AGPL)</td><td><strong style={{ color: copyleft.length > 0 ? "#dc2626" : "inherit" }}>{copyleft.length}</strong></td></tr>
              <tr><td style={{ color: unknown.length > 0 ? "#d97706" : "inherit" }}>Unknown / No License</td><td><strong style={{ color: unknown.length > 0 ? "#d97706" : "inherit" }}>{unknown.length}</strong></td></tr>
              <tr className="cert-table-total"><td>Total Packages</td><td><strong>{packages.length}</strong></td></tr>
            </tbody>
          </table>
        </div>
        {copyleft.length > 0 && (
          <div>
            <div className="cert-section-title" style={{ color: "#dc2626" }}>Copyleft Packages Requiring Review</div>
            <ul className="cert-risk-list">
              {copyleft.slice(0, 10).map((p, i) => (
                <li key={i}><strong>{p.name}</strong> ({p.license})</li>
              ))}
              {copyleft.length > 10 && <li>+{copyleft.length - 10} more</li>}
            </ul>
          </div>
        )}
      </div>

      <div className="cert-divider" />

      {/* Privacy Assessment */}
      <div className="cert-section-title">Privacy & Data Handling Assessment</div>
      <p className="cert-verdict-text">{result.privacy_verdict}</p>

      {/* Recommendations */}
      {result.recommendations && result.recommendations.length > 0 && (
        <>
          <div className="cert-divider" />
          <div className="cert-section-title">Recommendations</div>
          <ol className="cert-fix-list">
            {result.recommendations.map((rec, i) => (
              <li key={i}>{rec}</li>
            ))}
          </ol>
        </>
      )}

      {/* Footer */}
      <div className="cert-divider" />
      <div className="cert-footer">
        <div className="cert-footer-left">
          <div className="cert-footer-brand">Generated by Trojan Security</div>
          <div className="cert-footer-url">trojancli.com</div>
          <div className="cert-footer-disclaimer">
            This compliance report reflects the state of the codebase at the time of analysis.
            It is not a legal certification. Consult qualified legal counsel for formal compliance assessments.
            Re-scan regularly as dependencies and code evolve.
          </div>
        </div>
        <div className="cert-footer-qr">
          <QRCodeSVG value="https://trojancli.com" size={72} fgColor="#0a0a0a" bgColor="#ffffff" level="M" />
          <div className="cert-qr-label">trojancli.com</div>
        </div>
      </div>
    </div>,
    document.body
  );
}
