import { describe, expect, it } from "vitest";
import { tooltipOpensBelow, TOOLTIP_GAP_PX } from "./tooltipPlacement";

const viewport = { top: 48, bottom: 900 };

describe("tooltipOpensBelow", () => {
  it("opens above when there is room between the top bar and the icon", () => {
    const anchor = { top: 400, bottom: 414 };
    expect(tooltipOpensBelow(anchor, 80, viewport)).toBe(false);
  });

  it("opens below when the tip would clip the top bar", () => {
    // 10px of space above the icon after the 48px top bar, tip is 120px tall.
    const anchor = { top: 58, bottom: 72 };
    expect(tooltipOpensBelow(anchor, 120, viewport)).toBe(true);
  });

  it("counts the gap, not just the tip height", () => {
    const anchor = { top: 48 + 80, bottom: 48 + 80 + 14 };
    // Exactly the tip height fits, but the gap does not, so flip below.
    expect(tooltipOpensBelow(anchor, 80, viewport, TOOLTIP_GAP_PX)).toBe(true);
    expect(tooltipOpensBelow(anchor, 80 - TOOLTIP_GAP_PX, viewport, TOOLTIP_GAP_PX)).toBe(false);
  });

  it("picks the side with more room when neither side fits", () => {
    const tight = { top: 0, bottom: 200 };
    const anchor = { top: 40, bottom: 54 };
    // 40px above, 146px below; a 180px tip fits neither. Below has more room.
    expect(tooltipOpensBelow(anchor, 180, tight)).toBe(true);
    const nearBottom = { top: 150, bottom: 164 };
    expect(tooltipOpensBelow(nearBottom, 180, tight)).toBe(false);
  });
});
