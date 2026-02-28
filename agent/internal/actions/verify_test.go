package actions

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	"microedr/pkg/model"
)

func TestVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	action := model.Action{
		ActionID:      "a1",
		HostID:        "h1",
		TsUnixNano:    1,
		Type:          "kill_process",
		Params:        map[string]any{"pid": 123.0},
		Reason:        "test",
		ExpiresTsUnix: 2,
	}
	msg, _ := json.Marshal(signedAction{
		ActionID:      action.ActionID,
		HostID:        action.HostID,
		TsUnixNano:    action.TsUnixNano,
		Type:          action.Type,
		Params:        action.Params,
		Reason:        action.Reason,
		ExpiresTsUnix: action.ExpiresTsUnix,
	})
	action.SignatureBase64 = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
	if err := Verify(pub, action); err != nil {
		t.Fatalf("expected valid signature, got: %v", err)
	}
	action.SignatureBase64 = base64.StdEncoding.EncodeToString([]byte("wrong"))
	if err := Verify(pub, action); err == nil {
		t.Fatal("expected signature verification failure")
	}
}

