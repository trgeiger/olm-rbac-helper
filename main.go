/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package main

import (
	"github.com/trgeiger/olm-rbac-helper/cmd"
)

func main() {

	// serverVersionCmd := cmd.NewServerVersionCommand(genericclioptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr})
	cmd.Execute()
}
