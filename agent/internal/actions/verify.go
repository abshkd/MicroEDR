package actions

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"

	"microedr/pkg/model"
)

type signedAction struct {
	ActionID      string         `json:"action_id"`
	HostID        string         `json:"host_id"`
	TsUnixNano    int64          `json:"ts_unix_nano"`
	Type          string         `json:"type"`
	Params        map[string]any `json:"params"`
	Reason        string         `json:"reason"`
	ExpiresTsUnix int64          `json:"expires_ts_unix_nano"`
}

func Verify(pubKey ed25519.PublicKey, action model.Action) error {
	sig, err := base64.StdEncoding.DecodeString(action.SignatureBase64)
	if err != nil {
		return err
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
	if !ed25519.Verify(pubKey, msg, sig) {
		return errors.New("invalid action signature")
	}
	return nil
}

