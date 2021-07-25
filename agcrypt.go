package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/scrypt"
)

const KeyLen = 32

const packageSalt = "agcryptPglKIQwYK7LM75iM"

func mustRandRead(data []byte) {
	if _, err := rand.Read(data); err != nil {
		panic("can't read random data: " + err.Error())
	}
}

func b64encode(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}

func b64decode(data string) []byte {
	decoded, err := base64.URLEncoding.DecodeString(data)
	if err != nil {
		return nil
	}
	return decoded
}

type Key []byte

func (k Key) String() string {
	return b64encode(k)
}

func MakeKey(key []byte) (Key, error) {
	newKey := make([]byte, KeyLen)
	if len(key) != KeyLen || copy(newKey, key) != KeyLen {
		return nil, fmt.Errorf("wrong len %d (%d expected)", len(key), KeyLen)
	}
	return Key(key), nil
}

func MakeKeyFromFile(name string) (Key, error) {
	key, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return MakeKey(b64decode(string(key)))
}

func GenerateKey() (Key, error) {
	key := make([]byte, KeyLen)
	mustRandRead(key)
	return MakeKey(key)
}

func GenerateKeyFromPassphrase(passphrase string) (Key, error) {
	key, err := scrypt.Key([]byte(passphrase), []byte(packageSalt), 1<<15, 8, 1, KeyLen)
	if err != nil {
		return nil, err
	}
	return MakeKey(key)
}

type Machine struct {
	Key  Key
	aead cipher.AEAD
}

func NewMachine(key Key) (m *Machine, err error) {
	if key == nil {
		key, err = GenerateKey()
		if err != nil {
			return nil, err
		}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &Machine{Key: key, aead: aead}, nil
}

func (m *Machine) EncryptString(data string) (string, error) {
	nonce := make([]byte, m.aead.NonceSize())
	mustRandRead(nonce)
	ciphertext := m.aead.Seal(nil, nonce, []byte(data), nil)
	return b64encode(nonce) + "." + b64encode(ciphertext), nil
}

func (m *Machine) DecryptString(data string) (string, error) {
	split := strings.SplitN(data, ".", 2)
	nonce, ciphertext := b64decode(split[0]), b64decode(split[1])
	if len(nonce) != m.aead.NonceSize() {
		return "", fmt.Errorf("wrong nonce length: %d (%d expected)", len(nonce), m.aead.NonceSize())
	}

	plaintext, err := m.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func main() {
	genKey := flag.Bool("gen-key", false, "generate a new key")
	passphrase := flag.String("passphrase", "", "passphrase used for encryption/decryption or key generation")
	keyString := flag.String("key", "", "key")
	keyFile := flag.String("key-file", "", "read a key from the file")
	encrypt := flag.Bool("encrypt", true, "encryption mode")
	decrypt := flag.Bool("decrypt", false, "decryption mode")
	flag.Parse()

	var key Key
	var err error
	if *genKey {
		if len(*passphrase) > 0 {
			key, err = GenerateKeyFromPassphrase(*passphrase)
		} else {
			key, err = GenerateKey()
		}
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(key)
		return
	}

	switch {
	case len(*passphrase) > 0:
		key, err = GenerateKeyFromPassphrase(*passphrase)
	case len(*keyString) > 0:
		key, err = MakeKey(b64decode(*keyString))
	case len(*keyFile) > 0:
		key, err = MakeKeyFromFile(*keyFile)
	}
	if err != nil {
		log.Fatal(err)
	}

	machine, err := NewMachine(key)
	if err != nil {
		log.Fatal(err)
	}
	if key == nil {
		fmt.Println("encryption key:", machine.Key)
	}

	in := flag.Arg(0)
	if len(in) == 0 {
		stdin, err := io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatal(err)
		}
		in = string(stdin)
	}

	var out string
	if *decrypt || !*encrypt {
		out, err = machine.DecryptString(in)
	} else {
		out, err = machine.EncryptString(in)
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(out)
}
