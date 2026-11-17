# geris

Simple Eris cli in Go

## Usage

```
$ ./geris 
Usage: geris <command> [options]

Commands:
  encode [options]   Read file from stdin, store blocks, print URN to stdout
                       -block-size int   1 or 32 (default 32)
                       -secret string    64-char hex or passphrase (default: 32 zero bytes)
  decode <URN>       Reconstruct file from store and write to stdout
  pack <URN>         Bundle all blocks for URN into a tar stream on stdout
  unpack [URN]       Import tar block stream from stdin into store (verifies if URN given)

Environment:
  ERIS_STORE         Block directory (default: ~/.cache/eris/blocks)

Examples:
  geris encode < file.txt
  geris decode urn:eris:... > file.txt
  geris pack urn:eris:... | ssh host 'geris unpack urn:eris:...'
```

## Build

Simply do `go build -ldflags="-s -w"`
