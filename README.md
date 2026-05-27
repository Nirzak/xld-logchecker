# XLD Logchecker (Go)

A Go port of the [XLD Logchecker](https://github.com/OPSnet/xld_logchecker.py) project. This package provides verification of cryptographic signatures embedded in X Lossless Decoder (XLD) log files. 

It acts as both a standalone CLI tool and an importable Go package for downstream applications.

## Overview

XLD logs are verified by checking an embedded signature against a computed signature. The algorithm operates as follows:
1. The unsigned log text is hashed using a custom SHA-256 variant with a modified initial state.
2. The hex-encoded digest has `\nVersion=0001` appended to it.
3. The resulting string is passed through a proprietary block-scrambling algorithm that operates on 8-byte chunks.
4. The output is encoded using a non-standard base64 alphabet (with no padding).

This Go port is a complete re-implementation of the XLD log signing algorithm, requiring zero external dependencies.

## Installation

### CLI Tool
```bash
go install github.com/Nirzak/xld-logchecker/cmd/xld-logchecker@latest
```

### Go Package
```bash
go get github.com/Nirzak/xld-logchecker
```

## Usage

### Command Line
```bash
usage: xld-logchecker [--json] [--version] <file>

Verifies XLD log files.

positional arguments:
  file        path to the log file

optional arguments:
  --json      Output result as a JSON object
  --version   Print version and exit
```

Exit Codes:
- `0` - Valid signature
- `1` - Invalid signature (Malformed, Forged) or file error (Not a logfile)

### Go Library

```go
package main

import (
    "fmt"
    "github.com/Nirzak/xld-logchecker/xldlogchecker"
)

func main() {
    // From a file
    result := xldlogchecker.ParseLog("path/to/log.txt")
    fmt.Printf("Status: %s, Message: %s\n", result.Status, result.Message)

    // From in-memory content
    rawText := "X Lossless Decoder version..."
    result2 := xldlogchecker.VerifyContent(rawText)
    fmt.Printf("Status: %s, Message: %s\n", result2.Status, result2.Message)
}
```

The `Result` struct matches the output format of the original Python tool:
- `Status`: `"OK"`, `"BAD"`, or `"ERROR"`
- `Message`: `"OK"`, `"Malformed"`, `"Forged"`, `"Not a logfile"`, or `"error: cannot open file"`
