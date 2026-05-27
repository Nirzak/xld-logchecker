// Command xld-logchecker verifies X Lossless Decoder (XLD) log files.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Nirzak/xld-logchecker/xldlogchecker"
)

const version = "1.0.0"

func main() {
	jsonFlag := flag.Bool("json", false, "Output result as a JSON object")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: xld-logchecker [--json] [--version] <file>")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *versionFlag {
		fmt.Println("xld-logchecker " + version)
		return
	}

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}

	result := xldlogchecker.ParseLog(flag.Arg(0))

	if *jsonFlag {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(result)
	} else {
		fmt.Println(result.Message)
	}

	if result.Status != "OK" {
		os.Exit(1)
	}
}
