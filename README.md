# avault

A Go implementation of Ansible Vault encryption and decryption, usable as both a
command-line tool (`avault`) and an importable Go library.

Supports Ansible Vault formats **1.1** and **1.2**, including vault IDs (named
identities backed by separate password files).

[![Go Report Card](https://goreportcard.com/badge/github.com/emanspeaks/avault)](https://goreportcard.com/report/github.com/emanspeaks/avault)

## Installation

### Binary

Download a pre-built binary from the [releases page](https://github.com/emanspeaks/avault/releases).

| Platform | File |
| --- | --- |
| Linux x86-64 | `avault-linux-amd64` |
| Linux arm64 | `avault-linux-arm64` |
| macOS x86-64 | `avault-darwin-amd64` |
| macOS Apple Silicon | `avault-darwin-arm64` |
| Windows x86-64 | `avault-windows-amd64.exe` |

### From source

```sh
go install github.com/emanspeaks/avault@latest
```

---

## Command-line usage

### Global flags

These flags are accepted by every command.

| Flag | Short | Description |
| --- | --- | --- |
| `--vault-id label@source` | | Vault identity: `source` is a password file path or `prompt`. May be repeated. |
| `--vault-id-list path` | | Read vault identities from a list file containing `label@source` entries. |
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

#### Vault ID list files

Use `--vault-id-list` to load multiple identities from a text file containing
`label@source` entries. Blank lines and `#`-prefixed lines are ignored.
Relative paths inside the list file resolve relative to the directory
containing the list file itself.

A sample list file is included at [examples/vault-id-list.txt](examples/vault-id-list.txt).

The `source` part of a regular `--vault-id label@source` value is never
interpreted as a list file. It is always treated as either a password file path
or `prompt`.

`--vault-id-list` and `--vault-id` can be used together. When the same label
appears in both places, the `--vault-id` value wins. Additional `--vault-id`
values extend the list.

Example vault-id list file (`~/.vault/ids.txt`):

```text
# Master password
master@master.key

# Privilege escalation
become@./become.key
```

```sh
avault --vault-id-list ~/.vault/ids.txt decrypt secrets.yml

# Override one entry from the list and add another
avault decrypt \
  --vault-id-list ~/.vault/ids.txt \
  --vault-id master@~/.vault/override-master.key \
  --vault-id ci@~/.vault/ci.key \
  secrets.yml
```

#### Windows path support

On Windows, Unix-style paths (e.g. `/c/Users/user/.vault/key`) in vault-id
sources are automatically converted via `cygpath` when available. Tilde
expansion (`~/...`) is also supported.

---

### `encrypt`

Encrypts a file, writing the result to the input file by default. Use `--output`
to write to a different file instead.

```sh
# Interactive password prompt — produces format 1.1
avault encrypt secrets.yml

# Explicit password file — format 1.1
avault encrypt --vault-password-file ~/.vault/password secrets.yml

# Vault ID — produces format 1.2 with label embedded in the header
avault encrypt --vault-id master@~/.vault/master.key secrets.yml

# Load identities from a list file
avault encrypt --vault-id-list ~/.vault/ids.txt --encrypt-vault-id master secrets.yml

# Specify which identity to use when multiple identities are available
avault encrypt \
  --vault-id-list ~/.vault/ids.txt \
  --encrypt-vault-id master \
  secrets.yml

# Write encrypted output to a separate file
avault encrypt --vault-id master@~/.vault/master.key -o secrets.yml.enc secrets.yml

# Fixed salt — same plaintext + password + salt always produces identical ciphertext
avault encrypt --vault-password-file ~/.vault/password --salt mysaltstring secrets.yml

# Force re-encryption even if the output is already up to date
avault encrypt --vault-password-file ~/.vault/password --force secrets.yml
```

The `--encrypt-vault-id` flag names which identity to use for encryption. When
it is omitted and one or more identities are available, the first one is used.

#### Idempotency

Before encrypting, `avault encrypt` checks whether the output file already
exists and is a valid vault file. If it is, the tool decrypts it (using the
same identity that would be used to encrypt if it cannot be determined
automatically) and compares the result against
the incoming plaintext. When they match, the file is left unchanged and the
command exits successfully — no unnecessary re-encryption.

This makes `avault encrypt` safe to call repeatedly in scripts and CI pipelines
without producing spurious file changes.

Use `--force` to bypass this check and always re-encrypt, or `--salt` to make
repeated encryptions produce byte-for-byte identical output (useful for
deterministic builds or change-detection workflows).

#### `encrypt` flags

| Flag | Description |
| --- | --- |
| `--encrypt-vault-id label` | Identity label to use for encryption (must match an available vault identity label). |
| `--output path` | Write encrypted output to this file instead of overwriting the input. |
| `--salt value` | Fixed salt for deterministic encryption. The same salt + password + plaintext always produces identical ciphertext. Omit to use a random salt (default, more secure). |
| `--force` | Always re-encrypt, skipping the idempotency check against the existing output file. |

---

### `decrypt`

Decrypts a file, writing the result to the input file by default. Use `--output`
to write to a different file instead.

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

# Load identities from a list file
avault decrypt --vault-id-list ~/.vault/ids.txt secrets.yml

# Write decrypted output to a separate file
avault decrypt --vault-id master@~/.vault/master.key -o secrets.plain secrets.yml
```

When multiple `--vault-id` flags are provided, the tool reads the label from the
file's header and uses the matching identity. If the file carries a vault ID
label that does not match any supplied identity, decryption fails with an error.
Format 1.1 files (no label) use the password supplied via `--password` /
`--vault-password-file` as a fallback.

#### `decrypt` flags

| Flag | Description |
| --- | --- |
| `--output path` | `-o` Write decrypted output to this file instead of overwriting the input. |

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
import "github.com/emanspeaks/avault/vault"
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

// Encrypt with a fixed salt for deterministic output
ciphertext, err := vault.EncryptByteArrayWithIDAndSalt([]byte("my secret"), "password", "master", []byte("mysalt"))

// Decrypt works for both 1.1 and 1.2 format automatically
plaintext, err := vault.Decrypt(ciphertext, "password")

// Read just the vault ID from an encrypted string without decrypting
vaultID, err := vault.ReadVaultID(ciphertext)
// vaultID == "master" for format 1.2, "" for format 1.1

// Check whether a string is a valid vault-encrypted blob without decrypting
ok := vault.IsEncrypted(ciphertext)
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
