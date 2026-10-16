package updater

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRetryDue(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "marker")
	now := time.Now()

	if !retryDue(marker, now) {
		t.Fatal("missing marker should allow retry")
	}

	if err := os.WriteFile(marker, []byte("1.4.76"), 0644); err != nil {
		t.Fatal(err)
	}
	if retryDue(marker, now.Add(time.Minute)) {
		t.Fatal("retry one minute after a failed attempt should be blocked")
	}
	if !retryDue(marker, now.Add(failedUpdateRetryInterval+time.Second)) {
		t.Fatal("retry after the interval should be allowed")
	}
}
