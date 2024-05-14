package main

import (
	"bufio"
	"compress/gzip"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"

	"lukechampine.com/blake3"
)

const VERSION = "0.0.1"

func main() {
	parseCliOptions()

	if cliOpt.help {
		helpText()
		os.Exit(0)
	}
	if cliOpt.version {
		fmt.Println(VERSION)
		os.Exit(0)
	}

	if cliOpt.generate {
		G()
	}
	if cliOpt.sign {
		S()
	}
	if cliOpt.verify {
		V()
	}
}

func G() {
	if cliOpt.secKey == "" {
		fmt.Println("Missing seckey option '-s'")
		os.Exit(1)
	}
	if cliOpt.pubKey == "" {
		fmt.Println("Missing pubkey option '-p'")
		os.Exit(1)
	}

	passphrase := fetchPassphrase()

	pub, sec, err := GenerateKey(cryptorand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate keys: %v", err)
		os.Exit(1)
	}

	if err := WriteSecKey(sec, passphrase); err != nil {
		fmt.Printf("Failed to write secret key: %v", err)
		os.Exit(1)
	}

	if err := WritePubKey(pub); err != nil {
		fmt.Printf("Failed to write public key: %v", err)
		os.Exit(1)
	}

	os.Exit(0)
}

const MB = 1 << 10 << 10

func S() {
	if cliOpt.secKey == "" {
		fmt.Println("Missing seckey option '-s'")
		os.Exit(1)
	}
	if cliOpt.fin == "" {
		fmt.Println("Missing file-in option '-fin'")
		os.Exit(1)
	}
	if cliOpt.fout == "" {
		fmt.Println("Missing file-out option '-fout'")
		os.Exit(1)
	}

	var passphrase []byte
	if cliOpt.pp == "" {
		passphrase = fetchPassphrase()
	} else {
		passphrase = []byte(cliOpt.pp)
	}

	sec, err := ReadSecKey(cliOpt.secKey, passphrase)
	if err != nil {
		fmt.Printf("Failed to read secret key: %v", err)
		os.Exit(1)
	}

	// open file and read gzip content
	fin, err := os.Open(cliOpt.fin)
	if err != nil {
		fmt.Printf("Failed to open input file: %v", err)
		os.Exit(1)
	}
	defer fin.Close()

	gr, err := gzip.NewReader(fin)
	if err != nil {
		fmt.Printf("Input file not a valid gzip: %v", err)
		os.Exit(1)
	}

	hsh := blake3.New(32, nil)

	// run gzip content through hash
	for {
		_, err := io.CopyN(hsh, gr, int64(1*MB))
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			fmt.Printf("Failed to hash gzip content: %v", err)
			os.Exit(1)
		}
	}

	// reset input file
	fin.Seek(0, 0)
	gr.Reset(fin)

	// sign hash and create gzip header comment
	s := Sign(sec, hsh.Sum(nil))
	comment := CreateGZipComment(cliOpt.cmt, cliOpt.secKey, s)

	// write new gzip file with our comment and signature
	fout, err := os.OpenFile(cliOpt.fout, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		fmt.Printf("Failed to write gzip output: %v", err)
		os.Exit(1)
	}
	defer fout.Close()

	bufout := bufio.NewWriter(fout)
	defer bufout.Flush()

	gw := gzip.NewWriter(bufout)
	gw.Comment = comment

	// write new gzip file
	for {
		_, err := io.CopyN(gw, gr, int64(1*MB))
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			fmt.Printf("Failed to write gzip output: %v", err)
			os.Exit(1)
		}
	}

	gr.Close()
	gw.Close()
}

func V() {
	if cliOpt.pubKey == "" {
		fmt.Println("Missing pubkey option '-p'")
		os.Exit(1)
	}
	if cliOpt.fin == "" {
		fmt.Println("Missing file-in option '-fin'")
		os.Exit(1)
	}

	pub, err := ReadPubKey(cliOpt.pubKey)
	if err != nil {
		fmt.Printf("Failed to read public key: %v", err)
		os.Exit(1)
	}

	// open file and read gzip content
	fin, err := os.Open(cliOpt.fin)
	if err != nil {
		fmt.Printf("Failed to open input file: %v", err)
		os.Exit(1)
	}
	defer fin.Close()

	gr, err := gzip.NewReader(fin)
	if err != nil {
		fmt.Printf("Input file not a valid gzip: %v", err)
		os.Exit(1)
	}

	hsh := blake3.New(32, nil)

	// run gzip content through hash
	for {
		_, err := io.CopyN(hsh, gr, int64(1*MB))
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			fmt.Printf("Failed to hash gzip content: %v", err)
			os.Exit(1)
		}
	}

	// reset input file
	fin.Seek(0, 0)
	gr.Reset(fin)

	// Parse out signature
	sig, err := GetSignatureFromGZipComment(gr.Header.Comment)
	if err != nil {
		fmt.Printf("Failed to get signature from gzip comment: %v", err)
		os.Exit(1)
	}

	if Verify(pub, hsh.Sum(nil), sig) {
		fmt.Println("Verified")
	} else {
		fmt.Println("Failed")
		os.Exit(1)
	}
}
