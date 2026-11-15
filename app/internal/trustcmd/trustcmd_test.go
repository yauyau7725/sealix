
package trustcmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yauyau7725/sealix/app/internal/keys"
	"github.com/Yauyau7725/sealix/app/internal/truststore"
)

func invoke(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	rc := Run(args, &out, &errOut)
	return rc, out.String(), errOut.String()
}

func TestTrustCommands(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")
	publicPath := filepath.Join(dir, "pub.pem")

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	pemData := pem.EncodeToMemory(
		&pem.Block{Type: "PUBLIC KEY", Bytes: der},
	)
	if err := os.WriteFile(publicPath, pemData, 0600); err != nil {
		t.Fatal(err)
	}

	id, err := keys.Fingerprint(pub)
	if err != nil {
		t.Fatal(err)
	}

	rc, out, stderr := invoke(
		"add", "--store", path,
		"--key", publicPath,
		"--package", "contoh-app",
		"--keyid", id,
	)
	if rc != 0 || !strings.Contains(out, id) {
		t.Fatalf(
			"add: rc=%d stdout=%q stderr=%q",
			rc, out, stderr,
		)
	}

	for _, pkg := range []string{
		"contoh-app",
		"paket-lain",
	} {
		rc, _, stderr = invoke(
			"add", "--store", path,
			"--key", publicPath,
			"--package", pkg,
		)
		if rc != 0 {
			t.Fatalf("add/merge gagal: %s", stderr)
		}
	}

	store, err := truststore.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if len(store.Keys) != 1 ||
		len(store.Keys[0].Packages) != 2 {
		t.Fatalf("merge/idempotensi gagal: %+v", store)
	}

	rc, out, _ = invoke("list", "--store", path)
	if rc != 0 ||
		!strings.Contains(out, id) ||
		!strings.Contains(out, "paket-lain") {
		t.Fatalf("list gagal: %d %q", rc, out)
	}

	rc, _, _ = invoke(
		"add", "--store", path,
		"--key", publicPath,
		"--package", "contoh-app",
		"--keyid", strings.Repeat("0", 64),
	)
	if rc != 2 {
		t.Fatalf("pin salah: exit=%d, want=2", rc)
	}

	rc, _, _ = invoke(
		"remove", "--store", path, "--keyid", id,
	)
	if rc != 0 {
		t.Fatalf("remove exit=%d, want=0", rc)
	}

	rc, _, _ = invoke(
		"remove", "--store", path, "--keyid", id,
	)
	if rc != 2 {
		t.Fatalf("remove missing exit=%d, want=2", rc)
	}
}
