package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/scrypt"
)

type Key []byte

func (key Key) B64() string {
	return b64encode([]byte(key))
}

func (key Key) Hex() string {
	return hex.EncodeToString([]byte(key))
}

func GenerateKey() Key {
	key := make([]byte, 32)
	mustRandRead(key)
	return Key(key)
}

func GenerateKeyFromPassphrase(passphrase string) (Key, error) {
	key, err := scrypt.Key([]byte(passphrase), nil, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	return Key(key), nil
}

func NewKey(data []byte) (Key, error) {
	if len(data) != 32 {
		return nil, fmt.Errorf("wrong len %d (%d expected)", len(data), 32)
	}
	return Key(data), nil
}

func NewKeyFromFile(name string) (Key, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return NewKey(b64decode(string(data)))
}

func EncryptData(key Key, data string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	mustRandRead(nonce)

	ciphertext := aesgcm.Seal(nil, nonce, []byte(data), nil)

	return b64encode(nonce) + "." + b64encode(ciphertext), nil
}

func DecryptData(key Key, data string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	dataSplit := strings.SplitN(data, ".", 2)
	nonce, ciphertext := b64decode(dataSplit[0]), b64decode(dataSplit[1])
	if len(nonce) != aesgcm.NonceSize() {
		return "", fmt.Errorf("wrong nonce length: %d (%d expected)", len(nonce), aesgcm.NonceSize())
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

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

func main() {
	genKey := flag.Bool("gen-key", false, "generate a new key")
	genKeyPassphrase := flag.String("gen-key-passphrase", "", "generate a new key from the passphrase")
	keyString := flag.String("key", "", "key")
	keyFile := flag.String("key-file", "", "read key from the file")
	encode := flag.Bool("encode", true, "encode mode")
	decode := flag.Bool("decode", false, "decode mode")
	flag.Parse()

	if *genKey {
		fmt.Println(GenerateKey().B64())
		return
	}

	if len(*genKeyPassphrase) > 0 {
		key, err := GenerateKeyFromPassphrase(*genKeyPassphrase)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(key.B64())
		return
	}

	var key Key
	var err error
	switch {
	case len(*keyString) > 0:
		keyRaw := b64decode(*keyString)
		key, err = NewKey(keyRaw)
		if err != nil {
			log.Fatal(err)
		}
	case len(*keyFile) > 0:
		key, err = NewKeyFromFile(*keyFile)
		if err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatal("you should enter the key")
	}

	plaintext := flag.Arg(0)
	if len(plaintext) == 0 {
		log.Fatal("there's nothing to encrypt or decrypt")
	}

	switch {
	case *decode || !*encode:
		out, err := DecryptData(key, plaintext)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(out)
	default:
		out, err := EncryptData(key, plaintext)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(out)
	}
}
