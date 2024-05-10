//go:build linux

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
)

func fetchPassphrase() (passphrase []byte) {
	// See if we have a passphrase on stdin already
	cn := make(chan []byte)
	fd := int(os.Stdin.Fd())
	syscall.SetNonblock(fd, true)
	go func() {
		sc := bufio.NewReader(os.Stdin)
		s, e := sc.ReadString('\n')
		if e != nil {
			return
		}

		// remove newline
		if strings.HasSuffix(s, "\n") {
			s = strings.TrimSuffix(s, "\n")
		}

		cn <- []byte(s)
		close(cn)
	}()

	// if passphrase found on stdin, return it
	select {
	case passphrase = <-cn:
		syscall.SetNonblock(fd, false)
		return passphrase
	case <-time.After(time.Millisecond):
		syscall.SetNonblock(fd, false)
	}
	close(cn)

	if cliOpt.nopp {
		// Expected passphrase sent over stdin
		fmt.Println()
		os.Exit(1)
	}

	fmt.Printf("passphrase: ")
	p1, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		panic(err)
	}
	fmt.Println("") // move curser to newline

	if cliOpt.generate {
		fmt.Printf("confirm: ")
		p2, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			panic(err)
		}
		fmt.Println("") // move curser to newline

		if !bytes.Equal(p1, p2) {
			fmt.Printf("passphrase mismatch\n")
			os.Exit(1)
		}
	}

	passphrase = p1

	return passphrase
}
