# fkspm — FakeScript Package Manager

The official, zero-dependency CLI package manager for **FakeScript (`.fks`)** — designed to feel as familiar as `npm` or `pip` while preserving FakeScript's strictly zero-symbol manifest syntax.

## Build from Source

Requires Go 1.22+ (standard library only, zero external dependencies):

```powershell
# Windows
go build -o fkspm.exe .

# Linux / macOS
go build -o fkspm .
```

## Commands

| Command | Description |
| :--- | :--- |
| `fkspm init [name]` | Scaffold a new FakeScript project (`manifest.fks`, `main.fks`) |
| `fkspm search <query>` | Search packages in the registry index |
| `fkspm info <pkg>` | Show detailed metadata and versions for a package |
| `fkspm add <pkg> [version]` | Resolve, verify, cache, and install a package (+ transitive deps) |
| `fkspm remove <pkg>` | Uninstall a package and update `manifest.fks` / `lock.fks` |
| `fkspm install` | Install all dependencies listed in `manifest.fks` / `lock.fks` |
| `fkspm update [pkg]` | Update one or all dependencies to the latest registry version |
| `fkspm list` | List project dependencies and installation status |
| `fkspm cache dir` | Print the local package cache directory |
| `fkspm cache clean` | Clear cached tarballs and index |
| `fkspm version` | Print `fkspm` version |

## Zero-Symbol Manifest (`manifest.fks`)

```text
note FakeScript project manifest

package myapp version 0 1 0
author ChaiMaii
license WTFPL
description say My FakeScript application end

require http version 1 2 0
require json version 0 9 4
```

## Configuration

| Environment Variable | Default | Description |
| :--- | :--- | :--- |
| `FKSPM_INDEX_URL` | `https://chaimaii.github.io/fkspm-index/index.json` | Registry index JSON URL or local file path |
| `FKSPM_CACHE_DIR` | `~/.fkspm/cache` | Local download & tarball cache directory |

## Running Tests

```powershell
go test -v ./...
```

## License

Licensed under the [WTFPL](./LICENSE).
