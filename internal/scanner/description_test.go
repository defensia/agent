package scanner

import "testing"

// The server rejects a scan whose findings lack a description, so every
// finding Run returns must carry one, whatever the host looks like.
func TestRunFindingsAlwaysHaveDescription(t *testing.T) {
	for i, f := range Run() {
		if f.Description == "" {
			t.Errorf("finding %d (%s) has no description", i, f.CheckID)
		}
	}
}
