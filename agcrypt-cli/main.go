package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/sndb/agcrypt"
)

func main() {
	genKey := flag.Bool("gen-key", false, "generate a new key")
	passphrase := flag.String("passphrase", "", "passphrase used for encryption/decryption or key generation")
	keyString := flag.String("key", "", "key")
	keyFile := flag.String("key-file", "", "read a key from the file")
	encrypt := flag.Bool("encrypt", true, "encryption mode")
	decrypt := flag.Bool("decrypt", false, "decryption mode")
	flag.Parse()

	var key *agcrypt.Key
	var err error
	if *genKey {
		if len(*passphrase) > 0 {
			key, err = agcrypt.NewKeyFromPassphrase(*passphrase)
		} else {
			key, err = agcrypt.NewKey(nil)
		}
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(key)
		return
	}

	switch {
	case len(*passphrase) > 0:
		key, err = agcrypt.NewKeyFromPassphrase(*passphrase)
	case len(*keyString) > 0:
		key, err = agcrypt.NewKeyFromString(*keyString)
	case len(*keyFile) > 0:
		var b []byte
		b, err = os.ReadFile(*keyFile)
		if err != nil {
			log.Fatal(err)
		}
		key, err = agcrypt.NewKey(b)
	}
	if err != nil {
		log.Fatal(err)
	}

	if key == nil {
		key, err = agcrypt.NewKey(nil)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("encryption key:", key.String())
	}

	in := strings.Join(flag.Args(), " ")
	if len(in) == 0 {
		stdin, err := io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatal(err)
		}
		in = string(stdin)
	}

	var out string
	if *decrypt || !*encrypt {
		out, err = key.DecryptString(in)
	} else {
		out, err = key.EncryptString(in)
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(out)
}
