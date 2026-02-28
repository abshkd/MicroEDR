package uploader

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"microedr/agent/internal/spool"
)

type Client struct {
	httpClient *http.Client
	url        string
	tenantID   string
	hostID     string
	seq        int64
}

type batchRequest struct {
	TenantID string `json:"tenant_id"`
	HostID   string `json:"host_id"`
	Events   any    `json:"events"`
	Seq      int64  `json:"seq"`
}

func New(url, tenantID, hostID string) *Client {
	return &Client{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		url:        url,
		tenantID:   tenantID,
		hostID:     hostID,
		seq:        1,
	}
}

func (c *Client) FlushOnce(sp *spool.Spool) error {
	if err := sp.Seal(); err != nil {
		return err
	}
	segments, err := sp.ListSegments()
	if err != nil {
		return err
	}
	for i, segment := range segments {
		// Keep the newest segment active for future writes.
		if i == len(segments)-1 {
			continue
		}
		events, err := sp.ReadSegment(segment)
		if err != nil {
			return err
		}
		if len(events) == 0 {
			if err := sp.AckSegment(segment); err != nil {
				return err
			}
			continue
		}
		reqBody := batchRequest{
			TenantID: c.tenantID,
			HostID:   c.hostID,
			Events:   events,
			Seq:      c.seq,
		}
		b, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		resp, err := c.httpClient.Post(c.url, "application/json", bytes.NewReader(b))
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			return fmt.Errorf("ingest returned status %d", resp.StatusCode)
		}
		c.seq++
		if err := sp.AckSegment(segment); err != nil {
			return err
		}
	}
	return nil
}
