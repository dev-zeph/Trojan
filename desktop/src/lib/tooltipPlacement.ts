/** Gap between a .pt-info icon and its tooltip, matching App.css. */
export const TOOLTIP_GAP_PX = 8;
export const PT_INFO_BELOW_CLASS = "pt-info-below";
export const TOOLTIP_WIDTH_PX = 210;

export type Interval = { top: number; bottom: number };

/**
 * Whether a tooltip should open below its anchor because it does not fit above.
 * If neither side has enough room, pick the side with more space.
 */
export function tooltipOpensBelow(
  anchor: Interval,
  tooltipHeight: number,
  viewport: Interval,
  gap: number = TOOLTIP_GAP_PX,
): boolean {
  const needed = tooltipHeight + gap;
  const spaceAbove = anchor.top - viewport.top;
  const spaceBelow = viewport.bottom - anchor.bottom;
  if (spaceAbove >= needed) return false;
  if (spaceBelow >= needed) return true;
  return spaceBelow > spaceAbove;
}

/** Measure a .pt-info tooltip the same way the CSS paints it. */
export function measureTooltipHeight(text: string, doc: Document = document): number {
  const el = doc.createElement("div");
  el.style.cssText = [
    "position:absolute",
    "left:-9999px",
    "top:0",
    `width:${TOOLTIP_WIDTH_PX}px`,
    "box-sizing:content-box",
    "font:400 11px/1.45 var(--font-sans), sans-serif",
    "padding:8px 10px",
    "visibility:hidden",
    "white-space:pre-wrap",
    "overflow-wrap:break-word",
  ].join(";");
  el.textContent = text;
  doc.body.appendChild(el);
  const height = el.offsetHeight;
  el.remove();
  return height;
}

export function defaultTooltipViewport(doc: Document = document): Interval {
  const topbar = doc.querySelector(".topbar");
  const banner = doc.querySelector(".session-banner, .auth-expired, [role='alert']");
  let top = 0;
  if (topbar) top = Math.max(top, topbar.getBoundingClientRect().bottom);
  // A signed-out or expired-session banner sits under the topbar and also clips tips.
  if (banner) {
    const b = banner.getBoundingClientRect();
    if (b.bottom > top && b.top < 120) top = b.bottom;
  }
  const win = doc.defaultView ?? window;
  return { top, bottom: win.innerHeight };
}

/** Toggle .pt-info-below on hover/focus so the tip flips when it would clip above. */
export function attachPtInfoPlacement(
  root: ParentNode = document,
  getViewport: () => Interval = () => defaultTooltipViewport(),
): () => void {
  const place = (el: HTMLElement) => {
    const tip = el.getAttribute("data-tip") ?? "";
    const anchor = el.getBoundingClientRect();
    const height = measureTooltipHeight(tip, el.ownerDocument);
    const below = tooltipOpensBelow(anchor, height, getViewport());
    el.classList.toggle(PT_INFO_BELOW_CLASS, below);
  };

  const onEnter = (ev: Event) => {
    const el = ev.target;
    if (el instanceof HTMLElement && el.classList.contains("pt-info")) place(el);
  };

  root.addEventListener("pointerenter", onEnter, true);
  root.addEventListener("focusin", onEnter, true);
  return () => {
    root.removeEventListener("pointerenter", onEnter, true);
    root.removeEventListener("focusin", onEnter, true);
  };
}
