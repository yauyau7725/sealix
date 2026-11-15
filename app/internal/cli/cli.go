package cli

import (
	"fmt"
	"io"

	"github.com/FityatulhaqRosyidi/sealix/app/internal/keygencmd"
	"github.com/FityatulhaqRosyidi/sealix/app/internal/signcmd"
	"github.com/FityatulhaqRosyidi/sealix/app/internal/trustcmd"
	"github.com/FityatulhaqRosyidi/sealix/app/internal/verifycmd"
)

func Run(
	args []string,
	out io.Writer,
	errOut io.Writer,
	version string,
) int {
	if len(args) == 0 {
		help(out)
		return 2
	}
	switch args[0] {
	case "--help", "-h", "help":
		help(out)
		return 0
	case "--version", "version":
		fmt.Fprintln(out, "sealix", version)
		return 0
	case "trust":
		return trustcmd.Run(args[1:], out, errOut)
	case "verify":
		return verifycmd.Run(args[1:], out, errOut)
	case "keygen":
		return keygencmd.Run(args[1:], out, errOut)
	case "sign":
		return signcmd.Run(args[1:], out, errOut)
	default:
		fmt.Fprintf(
			errOut,
			"subcommand tidak dikenali: %s\n",
			args[0],
		)
		help(errOut)
		return 2
	}
}

func help(w io.Writer) {
	fmt.Fprint(w,

		`sealix - Sistem penandatanganan artefak cicd

Usage: 
		sealix <keygen|sign|trust|verify> [flags]

Commands:

		keygen
			--algorithm PROFIL
			--out PREFIX
			[--force]

		sign
			--file PATH
			--package NAME
			--version VERSION
			--key PEM
			--out BUNDLE
			[--force]

		trust add
			--key PEM
			--package NAME
			--store PATH
			[--keyid HEX]

		trust list
			--store PATH
		
		trust remove
			--keyid HEX
			--store PATH

		verify
			--file PATH
			--bundle PATH
			--trust-store PATH
			--package NAME
			--version VERSION
			[--json]
		
		--help        Bantuan
		--version     Versi Aplikasi

`)
}
