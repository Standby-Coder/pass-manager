package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	fieldEncPrefix = "enc:"
	fileMagic      = "PMENCDB\x00"
	saltLen        = 16
	nonceLen       = 12
	keyLen         = 32
)

// DeriveKey derives a 256-bit key from a passphrase using Argon2id.
func DeriveKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, keyLen)
}

// FieldEncryptor encrypts and decrypts individual database fields using AES-256-GCM.
type FieldEncryptor struct {
	gcm cipher.AEAD
}

// NewFieldEncryptor creates an encryptor from a passphrase. Returns nil if passphrase is empty.
func NewFieldEncryptor(passphrase string) (*FieldEncryptor, error) {
	if passphrase == "" {
		return nil, nil
	}

	key := DeriveKey(passphrase, []byte("pm-field-encryption-v1"))

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &FieldEncryptor{gcm: gcm}, nil
}

// Encrypt encrypts a plaintext string. Returns plaintext unchanged if encryptor is nil.
func (e *FieldEncryptor) Encrypt(plaintext string) (string, error) {
	if e == nil || plaintext == "" {
		return plaintext, nil
	}

	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := e.gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return fieldEncPrefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts an encrypted string. Returns the value unchanged if not encrypted or encryptor is nil.
func (e *FieldEncryptor) Decrypt(encrypted string) (string, error) {
	if e == nil || !strings.HasPrefix(encrypted, fieldEncPrefix) {
		return encrypted, nil
	}

	data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(encrypted, fieldEncPrefix))
	if err != nil {
		return "", err
	}

	if len(data) < e.gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:e.gcm.NonceSize()], data[e.gcm.NonceSize():]
	plaintext, err := e.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// EncryptFile encrypts a file using AES-256-GCM with a key derived from passphrase.
func EncryptFile(inputPath, outputPath, passphrase string) error {
	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}

	key := DeriveKey(passphrase, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	output := make([]byte, 0, len(fileMagic)+saltLen+len(nonce)+len(ciphertext))
	output = append(output, []byte(fileMagic)...)
	output = append(output, salt...)
	output = append(output, nonce...)
	output = append(output, ciphertext...)

	return os.WriteFile(outputPath, output, 0600)
}

// DecryptFile decrypts a file that was encrypted by EncryptFile.
func DecryptFile(inputPath, outputPath, passphrase string) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	magicLen := len(fileMagic)
	if len(data) < magicLen+saltLen+nonceLen {
		return errors.New("encrypted file too short")
	}

	if string(data[:magicLen]) != fileMagic {
		return errors.New("invalid encrypted file format")
	}

	offset := magicLen
	salt := data[offset : offset+saltLen]
	offset += saltLen
	nonce := data[offset : offset+nonceLen]
	offset += nonceLen
	ciphertext := data[offset:]

	key := DeriveKey(passphrase, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return errors.New("decryption failed: wrong key or corrupted file")
	}

	return os.WriteFile(outputPath, plaintext, 0600)
}

// IsEncryptedFile checks if a file has the encrypted file magic header.
func IsEncryptedFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	magic := make([]byte, len(fileMagic))
	if _, err := io.ReadFull(f, magic); err != nil {
		return false
	}

	return string(magic) == fileMagic
}

// EncryptData encrypts raw data with a passphrase (used for vault export).
func EncryptData(plaintext []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key := DeriveKey(passphrase, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	output := make([]byte, 0, saltLen+len(nonce)+len(ciphertext))
	output = append(output, salt...)
	output = append(output, nonce...)
	output = append(output, ciphertext...)

	return output, nil
}

// DecryptData decrypts data that was encrypted by EncryptData.
func DecryptData(data []byte, passphrase string) ([]byte, error) {
	if len(data) < saltLen+nonceLen {
		return nil, errors.New("encrypted data too short")
	}

	salt := data[:saltLen]
	nonce := data[saltLen : saltLen+nonceLen]
	ciphertext := data[saltLen+nonceLen:]

	key := DeriveKey(passphrase, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed: wrong password or corrupted data")
	}

	return plaintext, nil
}
