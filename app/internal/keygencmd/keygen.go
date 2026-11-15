package keygencmd

import (
	"errors"
	"flag"
	"fmt"
	"github.com/FityatulhaqRosyidi/sealix/app/internal/keys"
	"github.com/FityatulhaqRosyidi/sealix/app/internal/sigalg"
	"io"
)

func Run(args []string, out io.Writer, errOut io.Writer) int {
	f := flag.NewFlagSet("keygen", flag.ContinueOnError)
	f.SetOutput(errOut)

	algorithm := f.String("algorithm", "", "profil algoritma")
	outPrefix := f.String("out", "", "prefix keluaran")
	force := f.Bool("force", false, "timpa berkas yang sudah ada")

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
	if *algorithm == "" {
		fmt.Fprintln(errOut, "parameter --algorithm wajib diisi")
		return 2
	}
	if *outPrefix == "" {
		fmt.Fprintln(errOut, "parameter --out wajib diisi")
		return 2
	}

	alg, ok := sigalg.Lookup(*algorithm)
	if !ok {
		fmt.Fprintf(errOut, "algoritma tidak dikenal; pilihan: %s, %s, %s\n",
			sigalg.ProfileEd25519,
			sigalg.ProfileECDSA,
			sigalg.ProfileRSAPSS,
		)
		return 2
	}

	priv, err := alg.Generate()
	if err != nil {
		fmt.Fprintf(errOut, "gagal membuat kunci: %v\n", err)
		return 2
	}

	fp, err := keys.WriteKeyPair(*outPrefix, priv, *force)
	if err != nil {
		fmt.Fprintf(errOut, "gagal menulis pasangan kunci: %v\n", err)
		return 2
	}

	fmt.Fprintln(out, fp)
	return 0
}
