//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func fetchPassphrase() (passphrase []byte) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("passphrase: ")
	text, _ := reader.ReadString('\n')
	// remove newline
	if strings.HasSuffix(text, "\r\n") {
		text = strings.TrimSuffix(text, "\r\n")
	}

	if cliOpt.generate {
		fmt.Print("confirm: ")
		confirm, _ := reader.ReadString('\n')
		// remove newline
		if strings.HasSuffix(confirm, "\r\n") {
			confirm = strings.TrimSuffix(confirm, "\r\n")
		}

		fmt.Println("") // move curser to newline

		if text != confirm {
			fmt.Printf("passphrase mismatch\n")
			os.Exit(1)
		}
	}

	passphrase = []byte(text)

	return passphrase
}
