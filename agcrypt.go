package agcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

const packageSalt = "agcryptPglKIQwYK7LM75iM"

func b64encode(b []byte) string {
	return base64.URLEncoding.EncodeToString(b)
}

func b64decode(s string) []byte {
	b, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

func readCRNG(b []byte) {
	if _, err := rand.Read(b); err != nil {
		panic("cannot read CRNG: " + err.Error())
	}
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	readCRNG(b)
	return b
}

func newGCM(key []byte) (cipher.AEAD, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	return gcm, nil
}

func convertPassphrase(p string) ([]byte, error) {
	return scrypt.Key([]byte(p), []byte(packageSalt), 1<<15, 8, 1, KeySize)
}

const KeySize = 32

type Key struct {
	key []byte
	gcm cipher.AEAD
}

func NewKey(b []byte) (*Key, error) {
	if b == nil {
		b = randBytes(KeySize)
	}

	key := make([]byte, KeySize)
	if len(b) != KeySize || copy(key, b) != KeySize {
		return nil, fmt.Errorf("agcrypt: wrong key length: %v (%v expected)", len(b), KeySize)
	}

	gcm, err := newGCM(key)
	if err != nil {
		return nil, fmt.Errorf("agcrypt: cannot initialize GCM: %v", err)
	}

	return &Key{key, gcm}, nil
}

func NewKeyFromString(s string) (*Key, error) {
	return NewKey(b64decode(s))
}

func NewKeyFromPassphrase(p string) (*Key, error) {
	b, err := convertPassphrase(p)
	if err != nil {
		return nil, fmt.Errorf("agcrypt: cannot convert passphrase: %v", err)
	}
	return NewKey(b)
}

func (k *Key) Encrypt(plaintext []byte) ([]byte, error) {
	if k == nil {
		var err error
		k, err = NewKey(nil)
		if err != nil {
			return nil, err
		}
	}
	nonce := randBytes(k.gcm.NonceSize())
	return append(nonce, k.gcm.Seal(nil, nonce, []byte(plaintext), nil)...), nil
}

func (k *Key) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < k.gcm.NonceSize() {
		return nil, fmt.Errorf("agcrypt: ciphertext is too short: %v (at least %v expected)", len(ciphertext), k.gcm.NonceSize())
	}
	nonce, ctext := ciphertext[:k.gcm.NonceSize()], ciphertext[k.gcm.NonceSize():]
	return k.gcm.Open(nil, nonce, ctext, nil)
}

func (k *Key) EncryptString(plaintext string) (string, error) {
	ctext, err := k.Encrypt([]byte(plaintext))
	return b64encode(ctext), err
}

func (k *Key) DecryptString(ciphertext string) (string, error) {
	ptext, err := k.Decrypt(b64decode(ciphertext))
	return string(ptext), err
}

func (k *Key) Bytes() []byte {
	return k.key
}

func (k *Key) String() string {
	return b64encode(k.key)
}
