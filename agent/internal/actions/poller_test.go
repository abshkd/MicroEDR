package actions

import "testing"

func TestParsePID(t *testing.T) {
	pid, err := parsePID(map[string]any{"pid": float64(123)})
	if err != nil {
		t.Fatalf("expected pid parse success, got %v", err)
	}
	if pid != 123 {
		t.Fatalf("expected pid 123, got %d", pid)
	}

	pid, err = parsePID(map[string]any{"pid": "456"})
	if err != nil {
		t.Fatalf("expected pid parse success for string, got %v", err)
	}
	if pid != 456 {
		t.Fatalf("expected pid 456, got %d", pid)
	}

	if _, err := parsePID(map[string]any{}); err == nil {
		t.Fatal("expected parse failure for missing pid")
	}
}

func TestDeriveActionURLs(t *testing.T) {
	poll, res, err := deriveActionURLs("https://ingest.example.com/v1/events:batch")
	if err != nil {
		t.Fatalf("derive urls failed: %v", err)
	}
	if poll != "https://ingest.example.com/v1/actions:poll" {
		t.Fatalf("unexpected poll url: %s", poll)
	}
	if res != "https://ingest.example.com/v1/actions:result" {
		t.Fatalf("unexpected result url: %s", res)
	}
}
