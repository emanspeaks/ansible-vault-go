package vault

import (
	"errors"
	"os"
	"strings"
)

var (
	// ErrEmptyPassword is returned when password is empty.
	ErrEmptyPassword = errors.New("password is blank")

	// ErrInvalidSecret is returned when secret data is not formatted as Ansible secret.
	ErrInvalidSecret = errors.New("invalid secret")

	// ErrInvalidFormat is returned when the vault content has an unrecognized header.
	ErrInvalidFormat = errors.New("invalid secret format")

	// ErrInvalidPadding is returned when decryption produces invalid PKCS7 padding.
	ErrInvalidPadding = errors.New("invalid padding")
)

// IsEncrypted returns true if content begins with a valid Ansible Vault header.
func IsEncrypted(content string) bool {
	line, _, _ := strings.Cut(content, "\n")
	_, err := parseHeader(line)
	return err == nil
}

// EncryptByteArrayWithID encrypts input using password and embeds vaultID in the header.
// An empty vaultID produces vault format 1.1; a non-empty vaultID produces format 1.2.
func EncryptByteArrayWithID(input []byte, password string, vaultID string) (string, error) {
	return encryptWithSalt(input, password, vaultID, nil)
}

// EncryptByteArrayWithIDAndSalt is like EncryptByteArrayWithID but uses a caller-supplied
// salt for deterministic output. Providing the same salt, password, and plaintext always
// produces identical ciphertext, which makes re-encryption idempotent.
func EncryptByteArrayWithIDAndSalt(input []byte, password, vaultID string, salt []byte) (string, error) {
	return encryptWithSalt(input, password, vaultID, salt)
}

func encryptWithSalt(input []byte, password, vaultID string, salt []byte) (string, error) {
	if password == "" {
		return "", ErrEmptyPassword
	}

	if salt == nil {
		var err error
		salt, err = generateRandomBytes(saltLength)
		if err != nil {
			return "", err
		}
	}

	k := generateKey([]byte(password), salt)

	data, err := encrypt(input, k)
	if err != nil {
		return "", err
	}

	return encodeSecret(&secret{data: data, salt: salt}, k, vaultID)
}

// EncryptWithID encrypts input using password and vault ID (format 1.2 when vaultID non-empty).
func EncryptWithID(input string, password string, vaultID string) (string, error) {
	return EncryptByteArrayWithID([]byte(input), password, vaultID)
}

// EncryptByteArray encrypts the input []byte with the vault password (format 1.1).
func EncryptByteArray(input []byte, password string) (string, error) {
	return EncryptByteArrayWithID(input, password, "")
}

// Encrypt encrypts the input string with the vault password (format 1.1).
func Encrypt(input string, password string) (string, error) {
	return EncryptByteArray([]byte(input), password)
}

// EncryptFile encrypts input and writes it to path (format 1.1).
func EncryptFile(path string, input string, password string) error {
	result, err := Encrypt(input, password)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(result), 0o666)
}

// ReadVaultID returns the vault ID from the header of an encrypted vault string.
// Returns an empty string for format 1.1, the label for format 1.2.
func ReadVaultID(input string) (string, error) {
	line, _, _ := strings.Cut(input, "\n")
	h, err := parseHeader(line)
	if err != nil {
		return "", err
	}
	return h.label, nil
}

// Decrypt decrypts the input string with the vault password.
// Accepts both vault format 1.1 and 1.2.
func Decrypt(input string, password string) (string, error) {
	if password == "" {
		return "", ErrEmptyPassword
	}

	lines := strings.Split(input, "\n")
	if len(lines) < 2 {
		return "", ErrInvalidFormat
	}

	if _, err := parseHeader(lines[0]); err != nil {
		return "", err
	}

	decoded, err := hexDecode(strings.Join(lines[1:], "\n"))
	if err != nil {
		return "", err
	}

	s, err := decodeSecret(decoded)
	if err != nil {
		return "", err
	}

	k := generateKey([]byte(password), s.salt)
	if err := checkDigest(s, k); err != nil {
		return "", err
	}

	result, err := decrypt(s, k)
	if err != nil {
		return "", err
	}

	return result, nil
}

// DecryptFile decrypts the content of path with the vault password.
func DecryptFile(path string, password string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return Decrypt(string(data), password)
}
