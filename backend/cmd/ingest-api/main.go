package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"microedr/backend/internal/detection"
	"microedr/backend/internal/schema"
	"microedr/backend/internal/signing"
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
	signer, pubKeyB64, err := signing.NewFromBase64(os.Getenv("MICROEDR_ACTION_PRIVATE_KEY_B64"))
	if err != nil {
		log.Fatalf("failed to init action signer: %v", err)
	}
	detector := detection.NewRansomwareDetector(detection.Config{
		Window:              time.Duration(envOrInt("MICROEDR_RANSOM_WINDOW_SEC", 20)) * time.Second,
		MinWritesInWindow:   envOrInt("MICROEDR_RANSOM_WRITE_THRESHOLD", 120),
		MinDistinctPaths:    envOrInt("MICROEDR_RANSOM_UNIQUE_PATH_THRESHOLD", 40),
		ActionCooldown:      time.Duration(envOrInt("MICROEDR_RANSOM_COOLDOWN_SEC", 120)) * time.Second,
		ActionExpiry:        time.Duration(envOrInt("MICROEDR_ACTION_EXPIRY_SEC", 180)) * time.Second,
		DefaultReasonPrefix: "heuristic:ransomware_file_write_spike",
	}, signer)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/v1/actions:public_key", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"public_key_base64": pubKeyB64})
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
		autoActions := detector.Process(req.HostID, req.Events)
		for _, a := range autoActions {
			actionQueue.Enqueue(a)
			log.Printf("auto action queued host=%s action=%s type=%s reason=%s", a.HostID, a.ActionID, a.Type, a.Reason)
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
			if action.HostID == "" {
				http.Error(w, "missing host_id", http.StatusBadRequest)
				return
			}
			if action.ActionID == "" {
				action.ActionID = newID()
			}
			if action.Type == "" {
				http.Error(w, "missing type", http.StatusBadRequest)
				return
			}
		}
		if action.TsUnixNano == 0 {
			action.TsUnixNano = time.Now().UnixNano()
		}
		if action.ExpiresTsUnix == 0 {
			action.ExpiresTsUnix = time.Now().Add(5 * time.Minute).UnixNano()
		}
		if action.SignatureBase64 == "" {
			if err := signer.SignAction(&action); err != nil {
				http.Error(w, "failed to sign action", http.StatusInternalServerError)
				return
			}
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

	log.Printf("action public key (base64): %s", pubKeyB64)
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

func envOrInt(k string, fallback int) int {
	v := os.Getenv(k)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000000000000000000000000000"
	}
	return hex.EncodeToString(b[:])
}
