package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"microedr/pkg/model"
)

type Signer struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

type signedAction struct {
	ActionID      string         `json:"action_id"`
	HostID        string         `json:"host_id"`
	TsUnixNano    int64          `json:"ts_unix_nano"`
	Type          string         `json:"type"`
	Params        map[string]any `json:"params"`
	Reason        string         `json:"reason"`
	ExpiresTsUnix int64          `json:"expires_ts_unix_nano"`
}

func NewFromBase64(privateKeyB64 string) (*Signer, string, error) {
	if privateKeyB64 == "" {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, "", err
		}
		return &Signer{privateKey: priv, publicKey: pub}, base64.StdEncoding.EncodeToString(pub), nil
	}

	b, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil {
		return nil, "", fmt.Errorf("decode private key: %w", err)
	}
	switch len(b) {
	case ed25519.SeedSize:
		priv := ed25519.NewKeyFromSeed(b)
		pub := priv.Public().(ed25519.PublicKey)
		return &Signer{privateKey: priv, publicKey: pub}, base64.StdEncoding.EncodeToString(pub), nil
	case ed25519.PrivateKeySize:
		priv := ed25519.PrivateKey(b)
		pub := priv.Public().(ed25519.PublicKey)
		return &Signer{privateKey: priv, publicKey: pub}, base64.StdEncoding.EncodeToString(pub), nil
	default:
		return nil, "", errors.New("private key must be base64 of 32-byte seed or 64-byte private key")
	}
}

func (s *Signer) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(s.publicKey)
}

func (s *Signer) SignAction(action *model.Action) error {
	if action == nil {
		return errors.New("nil action")
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
		return err
	}
	sig := ed25519.Sign(s.privateKey, msg)
	action.SignatureBase64 = base64.StdEncoding.EncodeToString(sig)
	return nil
}
