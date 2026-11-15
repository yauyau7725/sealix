package verifycmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/yauyau7725/sealix/app/internal/bundle"
	"github.com/yauyau7725/sealix/app/internal/keys"
	"github.com/yauyau7725/sealix/app/internal/manifest"
	"github.com/yauyau7725/sealix/app/internal/result"
	"github.com/yauyau7725/sealix/app/internal/sigalg"
	"github.com/yauyau7725/sealix/app/internal/truststore"
	"io"
	"os"
	"path/filepath"
	"slices"
	"errors"
)

type Report struct {
	Valid     bool          `json:"valid"`
	Status    result.Status `json:"status"`
	Message   string        `json:"message"`
	Algorithm *string       `json:"algorithm"`
	KeyID     *string       `json:"keyid"`
	Package   *string       `json:"package"`
	Version   *string       `json:"version"`
}

func readBoundedInput(path string, max int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s bukan file reguler", path)
	}

	return io.ReadAll(io.LimitReader(f, int64(max)+1))
}

func Run(args []string, out io.Writer, errOut io.Writer) int {
	f := flag.NewFlagSet("verify", flag.ContinueOnError)

	f.SetOutput(errOut)

	file := f.String("file", "", "path artefak")

	bundlePath := f.String("bundle", "", "path bundle")

	trust := f.String("trust-store", "", "path trust store")

	pkg := f.String("package", "", "paket yang diharapkan")

	version := f.String("version", "", "versi yang diharapkan")

	jsonOut := f.Bool("json", false, "output JSON")

	report := Report{Status: result.InputError}

	emit := func(status result.Status, msg string) int {
		report.Status = status
		report.Message = msg
		report.Valid = status == result.OK

		if *jsonOut {
			if err := json.NewEncoder(out).Encode(report); err != nil {
				fmt.Fprintln(errOut, err)
				return 2
			}
		} else if status == result.OK {
			fmt.Fprintln(out, "OK:", msg)
		} else {
			fmt.Fprintf(out, "REJECTED [%s]: %s\n", status, msg)
		}

		if status != result.OK {
			fmt.Fprintf(errOut, "%s: %s\n", status, msg)
		}
		return result.ExitCode(status)
	}

	// INPUT ERROR
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return emit(result.InputError, err.Error())
	}

	if f.NArg() != 0 ||
		*file == "" ||
		*bundlePath == "" ||
		*trust == "" ||
		*pkg == "" ||
		*version == "" {
		return emit(
			result.InputError,
			"wajib: --file --bundle "+
				"--trust-store --package --version",
		)
	}

	artifact, err := os.Open(*file)
	if err != nil {
		return emit(result.InputError, err.Error())
	}

	defer artifact.Close()

	info, err := artifact.Stat()
	if err != nil {
		return emit(result.InputError, err.Error())
	}
	if !info.Mode().IsRegular() {
		return emit(result.InputError, "artefak bukan file reguler")
	}

	b, err := readBoundedInput(*bundlePath, bundle.MaxSize)
	if err != nil {
		return emit(result.InputError, err.Error())
	}
	
	trustData, err := readBoundedInput(*trust, truststore.MaxSize)
	if err != nil {
		return emit(result.InputError, err.Error())
	}

	// FORMAT ERROR
	raw, sig, err := bundle.Parse(b)
	if err != nil {
		return emit(result.FormatError, err.Error())
	}

	m, err := manifest.ParseStrict(raw)
	if err != nil {
		return emit(result.FormatError, err.Error())
	}
	
	report.Algorithm = &m.Algorithm
	report.KeyID = &m.KeyID
	report.Package = &m.Package
	report.Version = &m.Version

	store, err := truststore.Parse(trustData)
	if err != nil {
		return emit(result.FormatError, err.Error())
	}

	// UNSUPPORTED ALGO
	alg, ok := sigalg.Lookup(m.Algorithm)

	if !ok {
		return emit(result.UnsupportedAlgorithm, "profil algoritma tidak didukung")
	}

	// KEY NOT TRUSTED
	entry, ok := store.Lookup(m.KeyID)

	if !ok || entry.Algorithm != m.Algorithm || !slices.Contains(entry.Packages, *pkg) {
		return emit(result.KeyNotTrusted, "kunci tidak diizinkan untuk paket yang diharapkan")
	}

	pub, keyAlg, err := keys.ParsePublicPEM([]byte(entry.PublicKeyPEM))
	if err != nil {
		return emit(result.FormatError, err.Error())
	}

	if keyAlg.Name() != alg.Name() {
		return emit(result.KeyNotTrusted, "profil kunci tidak sesuai")
	}

	// INVALID SIGNATURE
	if !alg.Verify(pub, raw, sig) {
		return emit(result.InvalidSignature, "tanda tangan manifest tidak sah")
	}

	// METADATA MISMATCH
	if m.Package != *pkg || m.Version != *version || m.Artifact.Name != filepath.Base(*file) {
		return emit(result.MetadataMismatch, "metadata manifest tidak sesuai parameter")
	}

	// ARTIFACT MISMATCH
	h := sha256.New()

	size, err := io.Copy(h, artifact)
	if err != nil {
		return emit(result.InputError, err.Error())

	}

	actualHash := hex.EncodeToString(h.Sum(nil))

	if size != m.Artifact.Size || actualHash != m.Artifact.SHA256 {
		return emit(result.ArtifactMismatch, "isi atau ukuran artefak berbeda")
	}

	// OK
	return emit(result.OK, "signature, metadata, dan artefak valid")
}
