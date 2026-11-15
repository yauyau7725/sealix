package bundle 

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/yauyau7725/sealix/app/internal/jsonstrict"
)

const MaxSize = 64 * 1024

const Schema = "minisign-bundle/v1"

type wire struct {
	Schema string `json:"schema"`
	Manifest string `json:"manifest_b64"`
	Signature string `json:"signature_b64"`
}

func Marshal(manifest, sig []byte) []byte {
	b, _ := json.Marshal(wire{
		Schema: Schema,
		Manifest: base64.StdEncoding.EncodeToString(manifest,),
		Signature: base64.StdEncoding.EncodeToString(sig,),
	})
	return b
}

func Parse(data []byte) ([]byte, []byte, error) {
	if len(data) > MaxSize {
		return nil, nil, errors.New("Bundle memenuhi 64 KB",)
	}

	if _, err := jsonstrict.Parse(data); err != nil {
		return nil, nil, fmt.Errorf("Bundle JSON invalid: %w", err,)
	}

	var fields map[string]json.RawMessage

	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, nil, err
	}

	if len(fields) != 3 {
		return nil, nil, errors.New("Bundle harus tepat memiliki 3 field",)
	}

	for _, k := range []string{"schema", "manifest_b64", "signature_b64"} {
		value, ok := fields[k]

		if !ok || bytes.Equal(bytes.TrimSpace(value),[]byte("null"),) {
			return nil, nil, fmt.Errorf("Field %s hilang atau null", k)
		}
	}

	var b wire

	if err := json.Unmarshal(data, &b); err != nil {
		return nil, nil, err
	}

	if b.Schema != Schema {
		return nil, nil, errors.New("Schema bundle tidak didukung")
	}

	decode := func(s string) ([]byte, error) {
		out, err := base64.StdEncoding.Strict().DecodeString(s)

		if err != nil {
			return nil, err
		}

		encoded := base64.StdEncoding.EncodeToString(out)

		if !bytes.Equal([]byte(encoded), []byte(s),){
			return nil, errors.New("base64 tidak canonical")
		}

		return out, nil 
	}

	manifest, err := decode(b.Manifest)
	if err != nil {
		return nil, nil, fmt.Errorf("manifest_b64: %w", err,)
	}

	signature, err := decode(b.Signature)
	if err != nil {
		return nil, nil, fmt.Errorf("signature_b64: %w", err,)
	}

	return manifest, signature, nil
}

