package signcmd

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Yauyau7725/sealix/app/internal/bundle"
	"github.com/Yauyau7725/sealix/app/internal/keys"
	"github.com/Yauyau7725/sealix/app/internal/manifest"
)

func Run(args []string, out io.Writer, errOut io.Writer) int {
	f := flag.NewFlagSet("sign", flag.ContinueOnError)
	f.SetOutput(errOut)

	filePath := f.String("file", "", "path artefak")
	packageName := f.String("package", "", "nama paket")
	version := f.String("version", "", "versi")
	keyPath := f.String("key", "", "path private key")
	outPath := f.String("out", "", "path bundle")
	force := f.Bool("force", false, "timpa bundle")

	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if f.NArg() != 0 {
		fmt.Fprintln(errOut, "argumen posisional tidak diperbolehkan")
		return 2
	}

	var missing []string
	if *filePath == "" {
		missing = append(missing, "--file")
	}
	if *packageName == "" {
		missing = append(missing, "--package")
	}
	if *version == "" {
		missing = append(missing, "--version")
	}
	if *keyPath == "" {
		missing = append(missing, "--key")
	}
	if *outPath == "" {
		missing = append(missing, "--out")
	}
	if len(missing) != 0 {
		fmt.Fprintf(errOut, "parameter wajib diisi: %s\n", strings.Join(missing, ", "))
		return 2
	}

	absFile, err := filepath.Abs(*filePath)
	if err != nil {
		fmt.Fprintf(errOut, "gagal menentukan path artefak: %v\n", err)
		return 2
	}
	absOut, err := filepath.Abs(*outPath)
	if err != nil {
		fmt.Fprintf(errOut, "gagal menentukan path bundle: %v\n", err)
		return 2
	}
	if absFile == absOut {
		fmt.Fprintln(errOut, "path bundle tidak boleh sama dengan path artefak")
		return 2
	}
	if !*force {
		if _, err := os.Stat(*outPath); err == nil {
			fmt.Fprintln(errOut, "bundle sudah ada; gunakan --force untuk menimpa")
			return 2
		} else if !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(errOut, "gagal memeriksa bundle keluaran: %v\n", err)
			return 2
		}
	}

	keyData, err := os.ReadFile(*keyPath)
	if err != nil {
		fmt.Fprintf(errOut, "gagal membaca private key: %v\n", err)
		return 2
	}

	signer, alg, err := keys.ParsePrivatePEM(keyData)
	if err != nil {
		fmt.Fprintf(errOut, "gagal mengurai private key: %v\n", err)
		return 2
	}

	keyID, err := keys.Fingerprint(signer.Public())
	if err != nil {
		fmt.Fprintf(errOut, "gagal menghitung keyid: %v\n", err)
		return 2
	}

	artifactFile, err := os.Open(*filePath)
	if err != nil {
		fmt.Fprintf(errOut, "gagal membuka artefak: %v\n", err)
		return 2
	}
	defer artifactFile.Close()

	hash := sha256.New()
	size, err := io.Copy(hash, artifactFile)
	if err != nil {
		fmt.Fprintf(errOut, "gagal membaca artefak: %v\n", err)
		return 2
	}

	m := manifest.Manifest{
		Package:   *packageName,
		Version:   *version,
		Algorithm: alg.Name(),
		KeyID:     keyID,
		Artifact: manifest.Artifact{
			Name:   filepath.Base(*filePath),
			Size:   size,
			SHA256: hex.EncodeToString(hash.Sum(nil)),
		},
	}

	serializedManifest, err := m.Serialize()
	if err != nil {
		fmt.Fprintf(errOut, "gagal membuat manifest: %v\n", err)
		return 2
	}
	if len(serializedManifest) > manifest.MaxSize {
		fmt.Fprintln(errOut, "ukuran manifest melebihi batas maksimum")
		return 2
	}

	signature, err := alg.Sign(signer, serializedManifest)
	if err != nil {
		fmt.Fprintf(errOut, "gagal menandatangani manifest: %v\n", err)
		return 2
	}
	if !alg.Verify(signer.Public(), serializedManifest, signature) {
		fmt.Fprintln(errOut, "verifikasi tanda tangan internal gagal")
		return 2
	}

	data := bundle.Marshal(serializedManifest, signature)
	if len(data) > bundle.MaxSize {
		fmt.Fprintln(errOut, "ukuran bundle melebihi batas maksimum")
		return 2
	}

	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if *force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}

	bundleFile, err := os.OpenFile(*outPath, flags, 0o644)
	if err != nil {
		if !*force && errors.Is(err, os.ErrExist) {
			fmt.Fprintln(errOut, "bundle sudah ada; gunakan --force untuk menimpa")
		} else {
			fmt.Fprintf(errOut, "gagal membuka bundle keluaran: %v\n", err)
		}
		return 2
	}

	if _, err := bundleFile.Write(data); err != nil {
		_ = bundleFile.Close()
		_ = os.Remove(*outPath)
		fmt.Fprintf(errOut, "gagal menulis bundle: %v\n", err)
		return 2
	}
	if err := bundleFile.Close(); err != nil {
		_ = os.Remove(*outPath)
		fmt.Fprintf(errOut, "gagal menutup bundle: %v\n", err)
		return 2
	}

	fmt.Fprintf(errOut, "bundle ditulis ke %s (algoritma %s, keyid %s)\n",
		*outPath, alg.Name(), keyID)
	return 0
}
