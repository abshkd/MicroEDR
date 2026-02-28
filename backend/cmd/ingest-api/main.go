package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"microedr/backend/internal/schema"
	"microedr/backend/internal/storage"
	"microedr/pkg/model"
)

type batchRequest struct {
	TenantID string        `json:"tenant_id"`
	HostID   string        `json:"host_id"`
	Events   []model.Event `json:"events"`
	Seq      int64         `json:"seq"`
}

type actionResult struct {
	ActionID string `json:"action_id"`
	HostID   string `json:"host_id"`
	Status   string `json:"status"`
	Message  string `json:"message"`
}

func main() {
	addr := envOr("MICROEDR_INGEST_ADDR", ":8080")
	storePath := envOr("MICROEDR_EVENTS_FILE", "events.ndjson")
	store := storage.NewFileStore(storePath)
	actionQueue := newActionQueue()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/v1/events:batch", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req batchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if req.TenantID == "" || req.HostID == "" {
			http.Error(w, "missing tenant_id/host_id", http.StatusBadRequest)
			return
		}
		for _, ev := range req.Events {
			if err := schema.ValidateEvent(ev); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		if err := store.Append(req.Events); err != nil {
			http.Error(w, "storage error", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"accepted": len(req.Events),
			"rejected": 0,
			"next_seq": req.Seq + 1,
		})
	})
	mux.HandleFunc("/v1/actions:request", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var action model.Action
		if err := json.NewDecoder(r.Body).Decode(&action); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if action.HostID == "" || action.ActionID == "" || action.Type == "" {
			http.Error(w, "missing required action fields", http.StatusBadRequest)
			return
		}
		if action.ExpiresTsUnix == 0 {
			action.ExpiresTsUnix = time.Now().Add(5 * time.Minute).UnixNano()
		}
		actionQueue.Enqueue(action)
		w.WriteHeader(http.StatusAccepted)
	})
	mux.HandleFunc("/v1/actions:poll", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		hostID := r.URL.Query().Get("host_id")
		if hostID == "" {
			http.Error(w, "missing host_id", http.StatusBadRequest)
			return
		}
		actions := actionQueue.DequeueHost(hostID)
		_ = json.NewEncoder(w).Encode(map[string]any{"actions": actions})
	})
	mux.HandleFunc("/v1/actions:result", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var res actionResult
		if err := json.NewDecoder(r.Body).Decode(&res); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		log.Printf("action result host=%s action=%s status=%s msg=%s", res.HostID, res.ActionID, res.Status, res.Message)
		w.WriteHeader(http.StatusAccepted)
	})

	log.Printf("ingest-api listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

type queue struct {
	mu      sync.Mutex
	actions []model.Action
}

func newActionQueue() *queue {
	return &queue{actions: make([]model.Action, 0, 256)}
}

func (q *queue) Enqueue(a model.Action) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.actions = append(q.actions, a)
}

func (q *queue) DequeueHost(hostID string) []model.Action {
	now := time.Now().UnixNano()
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]model.Action, 0, len(q.actions))
	keep := make([]model.Action, 0, len(q.actions))
	for _, a := range q.actions {
		if a.ExpiresTsUnix > 0 && a.ExpiresTsUnix < now {
			continue
		}
		if a.HostID == hostID {
			out = append(out, a)
			continue
		}
		keep = append(keep, a)
	}
	q.actions = keep
	return out
}

func envOr(k, fallback string) string {
	v := os.Getenv(k)
	if v == "" {
		return fallback
	}
	return v
}
