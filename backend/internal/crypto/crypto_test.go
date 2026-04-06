package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFieldEncryptorNilPassthrough(t *testing.T) {
	enc, err := NewFieldEncryptor("")
	if err != nil {
		t.Fatal(err)
	}
	if enc != nil {
		t.Fatal("expected nil encryptor for empty passphrase")
	}

	result, err := enc.Encrypt("hello")
	if err != nil {
		t.Fatal(err)
	}
	if result != "hello" {
		t.Fatalf("expected passthrough, got %q", result)
	}

	result, err = enc.Decrypt("hello")
	if err != nil {
		t.Fatal(err)
	}
	if result != "hello" {
		t.Fatalf("expected passthrough, got %q", result)
	}
}

func TestFieldEncryptorRoundTrip(t *testing.T) {
	enc, err := NewFieldEncryptor("test-key-12345")
	if err != nil {
		t.Fatal(err)
	}

	plaintext := "super-secret-password"
	encrypted, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	if encrypted == plaintext {
		t.Fatal("encrypted should differ from plaintext")
	}

	if encrypted[:4] != "enc:" {
		t.Fatalf("expected enc: prefix, got %q", encrypted[:4])
	}

	decrypted, err := enc.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}

	if decrypted != plaintext {
		t.Fatalf("expected %q, got %q", plaintext, decrypted)
	}
}

func TestFieldEncryptorDifferentNonces(t *testing.T) {
	enc, err := NewFieldEncryptor("test-key-12345")
	if err != nil {
		t.Fatal(err)
	}

	plaintext := "same-password"
	enc1, _ := enc.Encrypt(plaintext)
	enc2, _ := enc.Encrypt(plaintext)

	if enc1 == enc2 {
		t.Fatal("same plaintext should produce different ciphertexts (random nonce)")
	}
}

func TestFieldEncryptorEmptyPlaintext(t *testing.T) {
	enc, err := NewFieldEncryptor("test-key")
	if err != nil {
		t.Fatal(err)
	}

	result, err := enc.Encrypt("")
	if err != nil {
		t.Fatal(err)
	}
	if result != "" {
		t.Fatalf("expected empty string, got %q", result)
	}
}

func TestFieldEncryptorWrongKey(t *testing.T) {
	enc1, _ := NewFieldEncryptor("key-one")
	enc2, _ := NewFieldEncryptor("key-two")

	encrypted, _ := enc1.Encrypt("secret")

	_, err := enc2.Decrypt(encrypted)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key")
	}
}

func TestFileEncryptionRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "plain.db")
	encPath := filepath.Join(tmpDir, "encrypted.db")
	outputPath := filepath.Join(tmpDir, "decrypted.db")

	content := []byte("SQLite format 3\x00... fake database content for testing")
	if err := os.WriteFile(inputPath, content, 0600); err != nil {
		t.Fatal(err)
	}

	passphrase := "test-db-key"

	if err := EncryptFile(inputPath, encPath, passphrase); err != nil {
		t.Fatal(err)
	}

	// Encrypted file should not match original
	encContent, _ := os.ReadFile(encPath)
	if string(encContent) == string(content) {
		t.Fatal("encrypted file should differ from original")
	}

	// Should be detected as encrypted
	if !IsEncryptedFile(encPath) {
		t.Fatal("encrypted file should be detected as encrypted")
	}

	if IsEncryptedFile(inputPath) {
		t.Fatal("plain file should not be detected as encrypted")
	}

	if err := DecryptFile(encPath, outputPath, passphrase); err != nil {
		t.Fatal(err)
	}

	decContent, _ := os.ReadFile(outputPath)
	if string(decContent) != string(content) {
		t.Fatal("decrypted content should match original")
	}
}

func TestFileDecryptionWrongKey(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "plain.db")
	encPath := filepath.Join(tmpDir, "encrypted.db")
	outputPath := filepath.Join(tmpDir, "decrypted.db")

	if err := os.WriteFile(inputPath, []byte("test data"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := EncryptFile(inputPath, encPath, "correct-key"); err != nil {
		t.Fatal(err)
	}

	err := DecryptFile(encPath, outputPath, "wrong-key")
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key")
	}
}

func TestDataEncryptionRoundTrip(t *testing.T) {
	plaintext := []byte(`{"entries": [{"title": "test", "password": "secret"}]}`)
	passphrase := "user-password-123"

	encrypted, err := EncryptData(plaintext, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := DecryptData(encrypted, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("expected %q, got %q", plaintext, decrypted)
	}
}

func TestDataDecryptionWrongPassword(t *testing.T) {
	plaintext := []byte("sensitive data")

	encrypted, err := EncryptData(plaintext, "correct-password")
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptData(encrypted, "wrong-password")
	if err == nil {
		t.Fatal("expected error when decrypting with wrong password")
	}
}
