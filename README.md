# ansible-vault-go

Go package to read/write Ansible Vault secrets

[![GoDoc](https://godoc.org/github.com/sosedoff/ansible-vault-go?status.svg)](https://godoc.org/github.com/sosedoff/ansible-vault-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/sosedoff/ansible-vault-go)](https://goreportcard.com/report/github.com/sosedoff/ansible-vault-go)

## Installation

```
go install github.com/codingtony/ansible-vault-go@latest
```

## Usage (command line)

### Flags for all commands

| Parameter | Description |
| ---- | ---- |
| `--password`, `-p` | Provide a password on the command line |
| `--ansible-vault-file` | Provide a password file |
| `--verbose`  | Debug output. Beware as it can contain sensible information |

If password flags are not provided, the user will be prompted for a vault password.

### Example : encrypt a file

Encrypt a file. Prompting for vault password.
```
ansible-vault-go encrypt /tmp/file_to_encrypt
```
Encrypt a file. Providing vault password file.
```
ansible-vault-go encrypt --ansible-vault-file /tmp/password_file /tmp/file_to_encrypt
```
Encrypt a file. Providing vault password as parameter.
```
ansible-vault-go encrypt -p"vault_password" /tmp/file_to_encrypt
```

### Example : decrypt a file

Decrypt a file. Prompting for vault password.
```
ansible-vault-go decrypt /tmp/file_to_encrypt
```
Decrypt a file. Providing vault password file.
```
ansible-vault-go decrypt --ansible-vault-file /tmp/password_file /tmp/file_to_encrypt
```
Decrypt a file. Providing vault password as parameter.
```
ansible-vault-go decrypt -p"vault_password" /tmp/file_to_encrypt
```
### Example : generate random content and encrypt it

This command is to generate a random alphanumeric string of length specified by the `--length` (or `-l` for short)  parameter. Default length is 32

```
ansible-vault-go random_text_encrypt -p"test" -l 40
$ANSIBLE_VAULT;1.1;AES256
34326565633335313262373962333766343264363934633566656564303631356139636164643730
3634353436353732323364656233653935346637346336340a393730313830623464633437363564
30316463663835616237393066666663666130343837656432343733333161656363646536346531
6334613865626431330a353938343833343838633062316433346365346533323031396437666663
66393636643065346332643134653438393966663662633965383962616633353139666265616531
3935393937373565396431383237663664336438656534383561
```

Full example with decryption

```
ansible-vault-go random_text_encrypt --verbose -p"test" -l 40 > /tmp/mysecret
2020-11-02 13:42:03 DEBUG cmd cmd_root.go:59 
2020-11-02 13:42:03 DEBUG cmd cmd_root.go:85 Vault Password used (between []): [test]
2020-11-02 13:42:03 DEBUG cmd cmd_encrypt.go:96 Generated string : iQE6Gll4VsfkDSmC4YCYyg9oxTVIsDtluICNfDcU

cat /tmp/mysecret 
$ANSIBLE_VAULT;1.1;AES256
62636266656438356330633735343964336465386639313032633237333435366332386565353037
3739373635303239376165643432383539623563663231310a353638313964626138666136383630
36356166343034663739396635323032623564343534363965313137383039313962393663633235
6133666365396630300a653063613738383532383133653437656536383264343864626265636230
62626366333431616539316566323834353764396666393464303734313237346338353161363638
3735336434653133306632313633386537353461393734326433

ansible-vault-go decrypt -p"test"  /tmp/mysecret
2020-11-02 13:46:06 INFO cmd cmd_decrypt.go:58 Decryption successful

cat /tmp/mysecret 
iQE6Gll4VsfkDSmC4YCYyg9oxTVIsDtluICNfDcU
```

## Usage (code)

```go
package main

import(
  "log"

  "github.com/codingtony/ansible-vault-go/vault"
)

func main() {
  // Encrypt secret data
  str, err := vault.Encrypt("secret", "password")

  // Decrypt secret data
  str, err := vault.Decrypt("secret", "password")

  // Write secret data to file
  err := vault.EncryptFile("path/to/secret/file", "secret", "password")

  // Read existing secret
  str, err := vault.DecryptFile("path/to/secret/file", "password")
}
```

## Reference

Check out the Ansible documentation regarding the Vault file format:

- https://docs.ansible.com/ansible/2.4/vault.html#vault-format

## License

MIT
