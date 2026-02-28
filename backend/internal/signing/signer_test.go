package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"

	"microedr/pkg/model"
)

func TestSignAction(t *testing.T) {
	s, pubB64, err := NewFromBase64("")
	if err != nil {
		t.Fatalf("new signer failed: %v", err)
	}
	pubRaw, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		t.Fatalf("decode pub failed: %v", err)
	}
	pub := ed25519.PublicKey(pubRaw)

	action := model.Action{
		ActionID:      "a1",
		HostID:        "h1",
		TsUnixNano:    123,
		Type:          "kill_process",
		Params:        map[string]any{"pid": 10},
		Reason:        "test",
		ExpiresTsUnix: 456,
	}
	if err := s.SignAction(&action); err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(action.SignatureBase64)
	if err != nil {
		t.Fatalf("decode sig failed: %v", err)
	}
	msg, err := json.Marshal(signedAction{
		ActionID:      action.ActionID,
		HostID:        action.HostID,
		TsUnixNano:    action.TsUnixNano,
		Type:          action.Type,
		Params:        action.Params,
		Reason:        action.Reason,
		ExpiresTsUnix: action.ExpiresTsUnix,
	})
	if err != nil {
		t.Fatalf("marshal msg failed: %v", err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("signature verification failed")
	}
}
