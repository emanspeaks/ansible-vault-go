package main

import "github.com/emanspeaks/ansible-vault-go/cmd"

var version string
var date string

func main() {
	cmd.Version = version
	cmd.BuildTime = date
	cmd.Execute()
}
