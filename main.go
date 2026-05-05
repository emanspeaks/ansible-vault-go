package main

import "github.com/emanspeaks/avault/cmd"

var version string
var date string

func main() {
	cmd.Version = version
	cmd.BuildTime = date
	cmd.Execute()
}
