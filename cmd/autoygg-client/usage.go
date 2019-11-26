package main

import (
  flag "github.com/spf13/pflag"
  "fmt"
  "os"
)

func usage(fs *flag.FlagSet) {
  fmt.Fprintf(os.Stderr, `
autoygg-client is a tool to register an Yggdrasil node with a gateway for internet egress.

Options:
`)
  fs.PrintDefaults()
}

