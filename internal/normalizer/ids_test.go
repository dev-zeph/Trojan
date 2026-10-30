package normalizer

import "testing"

func TestEnsureUniqueIDs(t *testing.T) {
	fs := []Finding{{ID: "nuclei-0"}, {ID: "nuclei-0"}, {ID: ""}, {ID: "nuclei-0-2"}, {ID: ""}, {ID: "a"}}
	changed := EnsureUniqueIDs(fs)
	seen := map[string]bool{}
	for _, f := range fs {
		if f.ID == "" || seen[f.ID] {
			t.Fatalf("IDs not unique/non-empty: %+v", fs)
		}
		seen[f.ID] = true
	}
	if fs[0].ID != "nuclei-0" || fs[3].ID != "nuclei-0-2" || fs[5].ID != "a" {
		t.Errorf("original unique IDs must be kept: %+v", fs)
	}
	if fs[1].ID == "nuclei-0-2" {
		t.Errorf("renamed duplicate stole another finding's ID: %+v", fs)
	}
	if changed != 3 {
		t.Errorf("changed = %d, want 3", changed)
	}
	if EnsureUniqueIDs(fs) != 0 {
		t.Error("second pass should change nothing")
	}
}
