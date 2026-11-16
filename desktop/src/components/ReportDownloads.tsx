// The two download buttons of the Security Report view. That view is shared by
// the simple and the full dashboard, so both get them from here.
export function ReportDownloads({ onTxt, onPdf }: { onTxt: () => void; onPdf: () => void }) {
  return (
    <>
      <button className="lab-export-btn" onClick={onTxt}>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        Export TXT
      </button>
      <button className="lab-export-btn" onClick={onPdf}>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
        Export PDF
      </button>
    </>
  );
}
