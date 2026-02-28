package actions

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"microedr/pkg/model"
)

type Poller struct {
	client     *http.Client
	hostID     string
	pollURL    string
	resultURL  string
	allow      map[string]struct{}
	pubKey     ed25519.PublicKey
	interval   time.Duration
	timeNowUTC func() time.Time
}

type pollResponse struct {
	Actions []model.Action `json:"actions"`
}

type actionResult struct {
	ActionID string `json:"action_id"`
	HostID   string `json:"host_id"`
	Status   string `json:"status"`
	Message  string `json:"message"`
}

func NewPoller(ingestEventsURL, hostID, serverPubKeyB64 string, allow []string, intervalSec int) (*Poller, error) {
	pollURL, resultURL, err := deriveActionURLs(ingestEventsURL)
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(serverPubKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decode server public key: %w", err)
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, errors.New("server public key must be 32 bytes (base64)")
	}
	if intervalSec <= 0 {
		intervalSec = 5
	}
	allowSet := make(map[string]struct{}, len(allow))
	for _, v := range allow {
		allowSet[v] = struct{}{}
	}
	return &Poller{
		client:     &http.Client{Timeout: 10 * time.Second},
		hostID:     hostID,
		pollURL:    pollURL,
		resultURL:  resultURL,
		pubKey:     ed25519.PublicKey(key),
		allow:      allowSet,
		interval:   time.Duration(intervalSec) * time.Second,
		timeNowUTC: time.Now,
	}, nil
}

func (p *Poller) Run(ctx context.Context) error {
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := p.runOnce(ctx); err != nil {
				continue
			}
		}
	}
}

func (p *Poller) runOnce(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.pollURL+"?host_id="+url.QueryEscape(p.hostID), nil)
	if err != nil {
		return err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("poll returned status %d", resp.StatusCode)
	}
	var polled pollResponse
	if err := json.NewDecoder(resp.Body).Decode(&polled); err != nil {
		return err
	}
	for _, a := range polled.Actions {
		status, msg := p.execute(a)
		_ = p.postResult(ctx, actionResult{
			ActionID: a.ActionID,
			HostID:   p.hostID,
			Status:   status,
			Message:  msg,
		})
	}
	return nil
}

func (p *Poller) execute(a model.Action) (status, message string) {
	if a.HostID != p.hostID {
		return "rejected", "host_id mismatch"
	}
	if a.ExpiresTsUnix > 0 && a.ExpiresTsUnix < p.timeNowUTC().UnixNano() {
		return "expired", "action expired"
	}
	if err := Verify(p.pubKey, a); err != nil {
		return "rejected", err.Error()
	}
	if _, ok := p.allow[a.Type]; !ok {
		return "rejected", "action not allowed by config"
	}

	switch a.Type {
	case "kill_process":
		pid, err := parsePID(a.Params)
		if err != nil {
			return "failed", err.Error()
		}
		if err := KillProcess(pid); err != nil {
			return "failed", err.Error()
		}
		return "ok", "process terminated"
	case "isolate_egress":
		if err := IsolateEgress(); err != nil {
			return "failed", err.Error()
		}
		return "ok", "egress isolation enabled"
	default:
		return "rejected", "unsupported action type"
	}
}

func (p *Poller) postResult(ctx context.Context, res actionResult) error {
	b, err := json.Marshal(res)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.resultURL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("result returned status %d", resp.StatusCode)
	}
	return nil
}

func parsePID(params map[string]any) (int, error) {
	raw, ok := params["pid"]
	if !ok {
		return 0, errors.New("missing pid param")
	}
	switch v := raw.(type) {
	case float64:
		if v < 1 || v != float64(int(v)) {
			return 0, errors.New("invalid pid value")
		}
		return int(v), nil
	case int:
		if v < 1 {
			return 0, errors.New("invalid pid value")
		}
		return v, nil
	case int64:
		if v < 1 {
			return 0, errors.New("invalid pid value")
		}
		return int(v), nil
	case string:
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, errors.New("invalid pid string")
		}
		if n < 1 {
			return 0, errors.New("invalid pid value")
		}
		return n, nil
	default:
		return 0, errors.New("unsupported pid type")
	}
}

func deriveActionURLs(ingestEventsURL string) (pollURL string, resultURL string, err error) {
	u, err := url.Parse(ingestEventsURL)
	if err != nil {
		return "", "", err
	}
	switch {
	case strings.HasSuffix(u.Path, "/v1/events:batch"):
		u.Path = strings.TrimSuffix(u.Path, "/v1/events:batch")
	case strings.HasSuffix(u.Path, "events:batch"):
		u.Path = strings.TrimSuffix(u.Path, "events:batch")
	default:
		u.Path = strings.TrimSuffix(u.Path, "/")
	}
	base := strings.TrimSuffix(u.String(), "/")
	return base + "/v1/actions:poll", base + "/v1/actions:result", nil
}
