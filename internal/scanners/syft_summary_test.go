package scanners

import (
	"strings"
	"testing"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// R3-P3-5: the SBOM item's location is the project folder ("."), never an
// absolute path.
func TestSyftSummaryFindingIsRelative(t *testing.T) {
	f := syftSummaryFinding(2)
	if f.FilePath != "." {
		t.Errorf("FilePath = %q, want \".\"", f.FilePath)
	}
	if f.Title != "SBOM: 2 packages inventoried" || f.Severity != normalizer.SeverityInfo || f.ID != "syft-0" {
		t.Errorf("unexpected finding %+v", f)
	}
	if f.Scanner != (&Syft{}).Name() || f.Category != (&Syft{}).Category() {
		t.Errorf("scanner/category %q/%q", f.Scanner, f.Category)
	}
	if strings.ContainsRune(f.RawMessage+f.Title, '\u2014') {
		t.Error("em dash in copy")
	}
}
