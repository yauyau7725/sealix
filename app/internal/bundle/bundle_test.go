package bundle

import (
    "bytes"
    "encoding/json"
    "strings"
    "testing"
)

func TestRoundtrip(t *testing.T) {
    manifest := []byte(`{"hello":1}`)
    signature := []byte{0, 1, 2, 255}

    raw := Marshal(manifest, signature)

    parsedManifest, parsedSignature, err := Parse(raw)

    if err != nil {
        t.Fatalf("roundtrip: %v", err)
    }

    if !bytes.Equal(parsedManifest, manifest) {
        t.Fatal("manifest berubah")
    }

    if !bytes.Equal(parsedSignature, signature) {
        t.Fatal("signature berubah")
    }
}

func TestReject(t *testing.T) {
    cases := []string{
        `{"schema":"minisign-bundle/v1","manifest_b64":"AA==","signature_b64":"AA==","extra":1}`,

        `{"schema":"minisign-bundle/v1","schema":"minisign-bundle/v1","manifest_b64":"AA==","signature_b64":"AA=="}`,

        `{"schema":"minisign-bundle/v1","manifest_b64":"AA= =","signature_b64":"AA=="}`,

        `{"schema":"minisign-bundle/v1","manifest_b64":null,"signature_b64":"AA=="}`,

        strings.Repeat("x", MaxSize+1),
    }

    for _, c := range cases {
        _, _, err := Parse([]byte(c))

        if err == nil {
            t.Errorf(
                "accepted invalid bundle: %.60s",
                c,
            )
        }
    }
}

func TestReorderedBundle(t *testing.T) {
    raw := Marshal(
        []byte("a"),
        []byte("b"),
    )

    var v map[string]any

    if err := json.Unmarshal(raw, &v); err != nil {
        t.Fatal(err)
    }

    reordered := `{
      "signature_b64": "Yg==",
      "manifest_b64": "YQ==",
      "schema": "minisign-bundle/v1"
    }`

    if _, _, err := Parse([]byte(reordered)); err != nil {
        t.Fatal(err)
    }
}