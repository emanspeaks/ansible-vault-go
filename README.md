# avault

A Go implementation of Ansible Vault encryption and decryption, usable as both a
command-line tool (`avault`) and an importable Go library.

Supports Ansible Vault formats **1.1** and **1.2**, including vault IDs (named
identities backed by separate password files).

[![Go Report Card](https://goreportcard.com/badge/github.com/emanspeaks/ansible-vault-go)](https://goreportcard.com/report/github.com/emanspeaks/ansible-vault-go)

## Installation

### Binary

Download a pre-built binary from the [releases page](https://github.com/emanspeaks/ansible-vault-go/releases).

| Platform | File |
| --- | --- |
| Linux x86-64 | `avault-linux-amd64` |
| Linux arm64 | `avault-linux-arm64` |
| macOS x86-64 | `avault-darwin-amd64` |
| macOS Apple Silicon | `avault-darwin-arm64` |
| Windows x86-64 | `avault-windows-amd64.exe` |

### From source

```sh
go install github.com/emanspeaks/ansible-vault-go@latest
```

---

## Command-line usage

### Global flags

These flags are accepted by every command.

| Flag | Short | Description |
| --- | --- | --- |
| `--vault-id label@source` | | Vault identity: `source` is a file path or `prompt`. May be repeated. |
| `--vault-password-file path` | | Read a single password from a file (no vault ID label). |
| `--password value` | `-p` | Provide the password directly on the command line. |
| `--verbose` | `-v` | Enable debug logging. May print sensitive values. |
| `--version` | | Print version and exit. |

`--vault-id` and `--vault-password-file` / `--password` may be combined; the
latter two act as an unlabeled fallback.

---

### Vault IDs

Ansible Vault format 1.2 embeds a label in the header line:

```text
$ANSIBLE_VAULT;1.2;AES256;master
```

This lets you maintain separate password files per identity (e.g. `master`,
`become`) and have the tool automatically use the right one when decrypting.

The `--vault-id` flag follows the same `label@source` convention as
`ansible-vault`:

```sh
# source is a file path
--vault-id master@~/.vault/master.key

# source is an interactive prompt
--vault-id master@prompt
```

---

### `encrypt`

Encrypts a file in place.

```sh
# Interactive password prompt — produces format 1.1
avault encrypt secrets.yml

# Explicit password file — format 1.1
avault encrypt --vault-password-file ~/.vault/password secrets.yml

# Vault ID — produces format 1.2 with label embedded in the header
avault encrypt --vault-id master@~/.vault/master.key secrets.yml

# Specify which identity to use when multiple --vault-id flags are present
avault encrypt \
  --vault-id master@~/.vault/master.key \
  --vault-id become@~/.vault/become.key \
  --encrypt-vault-id master \
  secrets.yml
```

The `--encrypt-vault-id` flag names which identity to use for encryption. When
it is omitted and `--vault-id` flags are present, the first one is used.

#### `encrypt` flags

| Flag | Description |
| --- | --- |
| `--encrypt-vault-id label` | Identity label to use for encryption (must match a `--vault-id` label). |

---

### `decrypt`

Decrypts a file in place.

```sh
# Interactive password prompt
avault decrypt secrets.yml

# Explicit password file
avault decrypt --vault-password-file ~/.vault/password secrets.yml

# Single vault ID
avault decrypt --vault-id master@~/.vault/master.key secrets.yml

# Multiple vault IDs — the tool matches the label in the file header automatically
avault decrypt \
  --vault-id master@~/.vault/master.key \
  --vault-id become@~/.vault/become.key \
  secrets.yml
```

When multiple `--vault-id` flags are provided, the tool reads the label from the
file's header and tries the matching identity first. If no label matches (e.g.
for a format 1.1 file), the first identity is used.

---

### `random_text_encrypt`

Generates a random alphanumeric string, encrypts it, and prints the ciphertext
to stdout.

```sh
# Default length 32, interactive prompt
avault random_text_encrypt

# Length 40, inline password
avault random_text_encrypt -p mypassword -l 40
```

Output:

```text
$ANSIBLE_VAULT;1.1;AES256
34326565633335313262373962333766343264363934633566656564303631356139636164643730
...
```

Pipe to a file and decrypt later:

```sh
avault random_text_encrypt -p mypassword -l 40 > /tmp/mysecret
avault decrypt -p mypassword /tmp/mysecret
cat /tmp/mysecret
```

#### `random_text_encrypt` flags

| Flag | Short | Description |
| --- | --- | --- |
| `--length n` | `-l` | Length of the generated string (default: 32). |

---

## Library usage

Import the `vault` package into your own Go code.

```go
import "github.com/emanspeaks/ansible-vault-go/vault"
```

### Encrypt / decrypt (format 1.1)

```go
// Encrypt a string
ciphertext, err := vault.Encrypt("my secret", "password")

// Encrypt a byte slice
ciphertext, err := vault.EncryptByteArray([]byte("my secret"), "password")

// Encrypt and write to a file
err := vault.EncryptFile("path/to/file", "my secret", "password")

// Decrypt a string
plaintext, err := vault.Decrypt(ciphertext, "password")

// Decrypt a file
plaintext, err := vault.DecryptFile("path/to/file", "password")
```

### Encrypt / decrypt with vault ID (format 1.2)

```go
// Encrypt with a vault ID label — produces format 1.2 header
ciphertext, err := vault.EncryptWithID("my secret", "password", "master")

// Encrypt a byte slice with a vault ID
ciphertext, err := vault.EncryptByteArrayWithID([]byte("my secret"), "password", "master")

// Decrypt works for both 1.1 and 1.2 format automatically
plaintext, err := vault.Decrypt(ciphertext, "password")

// Read just the vault ID from an encrypted string without decrypting
vaultID, err := vault.ReadVaultID(ciphertext)
// vaultID == "master" for format 1.2, "" for format 1.1
```

### Errors

```go
vault.ErrEmptyPassword  // password argument was blank
vault.ErrInvalidFormat  // unrecognized vault header
vault.ErrInvalidPadding // decryption produced invalid PKCS7 padding (wrong password)
```

---

## Vault format reference

| Version | Header | Notes |
| --- | --- | --- |
| 1.1 | `$ANSIBLE_VAULT;1.1;AES256` | Original format, no vault ID. |
| 1.2 | `$ANSIBLE_VAULT;1.2;AES256;label` | Adds a vault identity label. |

Both formats use AES-256-CTR encryption with PBKDF2-SHA256 key derivation
(10 000 iterations) and HMAC-SHA256 authentication, identical to the reference
Python implementation in Ansible.

See also: [Ansible Vault format documentation](https://docs.ansible.com/ansible/latest/vault_guide/vault_encrypting_content.html)

---

## License

MIT
