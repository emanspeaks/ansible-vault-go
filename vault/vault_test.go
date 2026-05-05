package vault

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncrypt(t *testing.T) {
	result, err := Encrypt("test", "")
	assert.Equal(t, ErrEmptyPassword, err)
	assert.Equal(t, "", result)

	result, err = Encrypt("", "password")
	assert.NoError(t, err)
	assert.Contains(t, result, "$ANSIBLE_VAULT;1.1;AES256")

	result, err = Encrypt("test", "password")
	assert.NoError(t, err)
	assert.Contains(t, result, "$ANSIBLE_VAULT;1.1;AES256")
}

func TestEncryptWithID(t *testing.T) {
	result, err := EncryptWithID("test", "", "master")
	assert.Equal(t, ErrEmptyPassword, err)
	assert.Equal(t, "", result)

	result, err = EncryptWithID("test", "password", "master")
	assert.NoError(t, err)
	assert.Contains(t, result, "$ANSIBLE_VAULT;1.2;AES256;master")

	result, err = EncryptWithID("test", "password", "become")
	assert.NoError(t, err)
	assert.Contains(t, result, "$ANSIBLE_VAULT;1.2;AES256;become")

	// Empty vault ID falls back to 1.1 format
	result, err = EncryptWithID("test", "password", "")
	assert.NoError(t, err)
	assert.Contains(t, result, "$ANSIBLE_VAULT;1.1;AES256")
	assert.NotContains(t, result, "1.2")
}

func TestDecrypt(t *testing.T) {
	sample := `$ANSIBLE_VAULT;1.1;AES256
66636665376466363035323339653038313631366530366139353930363639396263336538656638
3232656465323265663737633039363037323039393039620a303065353563633261633964623139
32363666633230313364356230623830383134383432633932333630626462316434333137373131
6362373633313532650a313362613134656433663238333163323865666237366161366164383266
3936`

	empty := `$ANSIBLE_VAULT;1.1;AES256
62613733343936633739383863623438363535336535643539623734313533663838643661313230
6231343261616531393039313562663037303566356437370a643965616335653166653032656566
37646235336630613233633233396136636434303338373563366237383939616361313638376434
6464623462326236650a663235666338633036633336303632343834633164323537333030363061
3163`

	result, err := Decrypt(sample, "password")
	assert.NoError(t, err)
	assert.Equal(t, "test\n", result)

	result, err = Decrypt(sample, "invalid pass")
	assert.Equal(t, err.Error(), "invalid password")
	assert.Empty(t, result)

	result, err = Decrypt("invalid data", "password")
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "invalid secret format")

	result, err = Decrypt("$ANSIBLE_VAULT;2.0;AES256\n636235663265383266346139", "password")
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "invalid secret format")

	result, err = Decrypt("$ANSIBLE_VAULT;1.1;AES256\n636235663265383266346139", "password")
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "invalid secret")

	result, err = Decrypt(empty, "password")
	assert.NoError(t, err)
	assert.Equal(t, "", result)

	result, err = Decrypt("input", "")
	assert.Equal(t, err, ErrEmptyPassword)
	assert.Equal(t, "", result)
}

func TestEncryptDecrypt(t *testing.T) {
	result, err := Encrypt("test\n", "password")
	assert.NoError(t, err)
	assert.Contains(t, result, "$ANSIBLE_VAULT;1.1;AES256")

	result, err = Decrypt(result, "password")
	assert.NoError(t, err)
	assert.Equal(t, "test\n", result)
}

func TestEncryptDecryptWithID(t *testing.T) {
	const plaintext = "my secret value\n"
	const password = "vaultpassword"
	const vaultID = "master"

	encrypted, err := EncryptWithID(plaintext, password, vaultID)
	require.NoError(t, err)
	assert.Contains(t, encrypted, "$ANSIBLE_VAULT;1.2;AES256;master")

	decrypted, err := Decrypt(encrypted, password)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestReadVaultID(t *testing.T) {
	v11 := `$ANSIBLE_VAULT;1.1;AES256
aabbcc`
	id, err := ReadVaultID(v11)
	assert.NoError(t, err)
	assert.Equal(t, "", id)

	v12 := `$ANSIBLE_VAULT;1.2;AES256;master
aabbcc`
	id, err = ReadVaultID(v12)
	assert.NoError(t, err)
	assert.Equal(t, "master", id)

	v12noLabel := `$ANSIBLE_VAULT;1.2;AES256
aabbcc`
	id, err = ReadVaultID(v12noLabel)
	assert.NoError(t, err)
	assert.Equal(t, "", id)

	invalid := `not a vault file`
	_, err = ReadVaultID(invalid)
	assert.Equal(t, ErrInvalidFormat, err)
}
