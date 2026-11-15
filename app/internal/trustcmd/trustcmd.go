package trustcmd

import (
	"errors"
	"flag"
	"fmt"
	"github.com/Yauyau7725/sealix/app/internal/keys"
	"github.com/Yauyau7725/sealix/app/internal/truststore"
	"io"
	"os"
	"strings"
)

func Run(args []string, out io.Writer, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, "usage: trust add|list|remove")
		return 2
	}

	switch args[0] {
	case "add":
		return add(args[1:], out, errOut)
	case "list":
		return list(args[1:], out, errOut)
	case "remove":
		return remove(args[1:], out, errOut)
	}

	fmt.Fprintln(errOut, "subcommand trust tidak dikenali")
	return 2
}

func flags(name string, stderr io.Writer) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)

	f.SetOutput(stderr)

	return f
}

func getStore(path string, create bool) (*truststore.Store, error) {
	s, err := truststore.Load(path)

	if errors.Is(err, os.ErrNotExist) && create {
		return truststore.Empty(), nil
	}

	return s, err
}

func add(args []string, out io.Writer, errOut io.Writer) int {
	f := flags("trust add", errOut)

	store := f.String("store", "", "path trust store")
	public := f.String("key", "", "path public key PEM")
	pkg := f.String("package", "", "nama paket")
	pin := f.String("keyid", "", "fingerprint yang diharapkan (opsional)")

	if f.Parse(args) != nil ||
		f.NArg() != 0 ||
		*store == "" ||
		*public == "" ||
		*pkg == "" {

		fmt.Fprintln(
			errOut,
			"usage: trust add --key PEM --package NAME --store PATH "+
				"[--keyid HEX]",
		)

		return 2
	}

	b, err := os.ReadFile(*public)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}

	pub, alg, err := keys.ParsePublicPEM(b)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}

	fp, err := keys.Fingerprint(pub)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}

	if *pin != "" && *pin != fp {
		fmt.Fprintln(errOut, "fingerprint tidak cocok dengan --keyid")
		return 2
	}

	s, err := getStore(*store, true)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}

	created, err := s.Add(pub, *pkg)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}

	if err = s.Save(*store); err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}

	fmt.Fprintf(
		out,
		"keyid=%s algorithm=%s package=%s created=%t\n",
		fp,
		alg.Name(),
		*pkg,
		created,
	)

	return 0
}

func list(args []string, out io.Writer, errOut io.Writer) int {
	f := flags("trust list", errOut)

	path := f.String("store", "", "path trust store")

	if f.Parse(args) != nil || f.NArg() != 0 || *path == "" {
		fmt.Fprintln(errOut, "usage: trust list --store PATH")
		return 2
	}

	s, err := truststore.Load(*path)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}

	for _, e := range s.Keys {
		fmt.Fprintf(
			out,
			"%s %s %s\n",
			e.KeyID,
			e.Algorithm,
			strings.Join(e.Packages, ","),
		)
	}
	return 0
}

func remove(args []string, out io.Writer, errOut io.Writer) int {
	f := flags("trust remove", errOut)

	path := f.String("store", "", "path trust store")
	id := f.String("keyid", "", "fingerprint")

	if f.Parse(args) != nil ||
		f.NArg() != 0 ||
		*path == "" ||
		*id == "" {
		fmt.Fprintln(
			errOut,
			"usage: trust remove --keyid HEX --store PATH",
		)
		return 2
	}

	s, err := truststore.Load(*path)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}

	if err = s.Remove(*id); err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}

	if err = s.Save(*path); err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}

	fmt.Fprintln(out, "removed", *id)

	return 0
}

// # Tambah key
// ./sealix trust add \
//   --key public.pem \
//   --package contoh-app
//   --store ci/trust.json

// # Tampilkan semua key
// ./sealix trust list \
//   --store ci/trust.json

// # Hapus key
// ./sealix trust remove \
//   --keyid FINGERPRINT_64_HEX \
//   --store ci/trust.json
