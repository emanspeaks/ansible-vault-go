package vault

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

const (
	vaultFormatV11 = "$ANSIBLE_VAULT;1.1;AES256"
	vaultFormatV12 = "$ANSIBLE_VAULT;1.2;AES256"
	vaultHeader    = vaultFormatV11
)

type secret struct {
	salt []byte
	hmac []byte
	data []byte
}

// parseHeader validates and parses the vault header line.
// Returns the vault ID (empty string for 1.1 format) or ErrInvalidFormat.
func parseHeader(line string) (string, error) {
	line = strings.TrimSpace(line)
	switch {
	case line == vaultFormatV11:
		return "", nil
	case line == vaultFormatV12:
		return "", nil
	case strings.HasPrefix(line, vaultFormatV12+";"):
		return strings.TrimPrefix(line, vaultFormatV12+";"), nil
	default:
		return "", ErrInvalidFormat
	}
}

func decodeSecret(input string) (*secret, error) {
	lines := strings.SplitN(input, "\n", 3)
	if len(lines) != 3 {
		return nil, errors.New("invalid secret")
	}

	salt, err := hex.DecodeString(lines[0])
	if err != nil {
		return nil, err
	}

	mac, err := hex.DecodeString(lines[1])
	if err != nil {
		return nil, err
	}

	data, err := hex.DecodeString(lines[2])
	if err != nil {
		return nil, err
	}

	return &secret{salt, mac, data}, nil
}

func encodeSecret(s *secret, k *key, vaultID string) (string, error) {
	h := hmac.New(sha256.New, k.hmacKey)
	h.Write(s.data)

	inner := strings.Join([]string{
		hex.EncodeToString(s.salt),
		hex.EncodeToString(h.Sum(nil)),
		hex.EncodeToString(s.data),
	}, "\n")

	header := vaultFormatV11
	if vaultID != "" {
		header = vaultFormatV12 + ";" + vaultID
	}

	return header + "\n" + wrapText(hex.EncodeToString([]byte(inner))), nil
}

func checkDigest(s *secret, k *key) error {
	h := hmac.New(sha256.New, k.hmacKey)
	h.Write(s.data)
	if !hmac.Equal(h.Sum(nil), s.hmac) {
		return errors.New("invalid password")
	}
	return nil
}

func wrapText(text string) string {
	src := []byte(text)
	result := make([]byte, 0, len(src)+len(src)/80)
	for i, b := range src {
		if i > 0 && i%80 == 0 {
			result = append(result, '\n')
		}
		result = append(result, b)
	}
	return string(result)
}

func hexDecode(input string) (string, error) {
	input = strings.TrimSpace(input)
	input = strings.ReplaceAll(input, "\r", "")
	input = strings.ReplaceAll(input, "\n", "")

	decoded, err := hex.DecodeString(input)
	if err != nil {
		return "", err
	}

	return string(decoded), nil
}
