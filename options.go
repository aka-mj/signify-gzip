package main

import (
	"flag"
	"fmt"
)

type cliOptions struct {
	generate bool
	sign     bool
	verify   bool
	version  bool

	secKey string
	pubKey string
	fout   string
	fin    string
	cmt    string
	nopp   bool
	pp     string

	help bool
}

var cliOpt cliOptions

func parseCliOptions() {
	flag.BoolVar(&cliOpt.generate, "G", false, "Generate")
	flag.BoolVar(&cliOpt.sign, "S", false, "Sign")
	flag.BoolVar(&cliOpt.verify, "V", false, "Verify")
	flag.BoolVar(&cliOpt.version, "v", false, "Version")

	flag.StringVar(&cliOpt.secKey, "s", "", "secret key")
	flag.StringVar(&cliOpt.pubKey, "p", "", "public key")
	flag.StringVar(&cliOpt.fout, "fout", "", "file out")
	flag.StringVar(&cliOpt.fin, "fin", "", "file in")
	flag.StringVar(&cliOpt.cmt, "c", "", "comment")
	flag.BoolVar(&cliOpt.nopp, "n", false, "don't ask for passphrase, read from stdin")
	flag.StringVar(&cliOpt.pp, "passphrase", "", "passphrase")

	flag.BoolVar(&cliOpt.help, "h", false, "print help")
	flag.Parse()
}

func helpText() {
	fmt.Println(`
     signify-gzip -G [-n] [-c comment] -p pubkey -s seckey
     signify-gzip -S [-n] [-passphrase phrase] -s seckey -fin input-file -fout output-file
     signify-gzip -V -p pubkey -fin input-file
	`)
}
