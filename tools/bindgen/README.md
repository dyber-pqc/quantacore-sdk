# QUAC 100 Binding Generator (bindgen)

A code generation tool that produces language bindings for the QuantaCore SDK from C header files. Generates idiomatic wrappers for Python, Rust, Go, Java, C#, and Node.js.

## Features

- **Automatic Header Parsing**: Parses QUAC SDK C headers to extract types, functions, and constants
- **Multi-Language Output**: Generates bindings for 6+ programming languages
- **Idiomatic Wrappers**: Produces language-native APIs, not just raw FFI bindings
- **Type Mapping**: Automatically maps C types to appropriate language equivalents
- **Documentation Transfer**: Copies Doxygen comments to target language doc formats
- **Version Synchronization**: Embeds SDK version info in generated bindings

## Supported Languages

| Language | Output | Features |
|----------|--------|----------|
| Python | `quac100.py`, `_quac100.pyi` | ctypes bindings, type hints, async support |
| Rust | `lib.rs`, `ffi.rs` | Safe wrappers, Result types, derive macros |
| Go | `quac100.go` | cgo bindings, error handling, context support |
| Java | `QUAC100.java`, JNI | JNI bindings, exceptions, AutoCloseable |
| C# | `QUAC100.cs` | P/Invoke, IDisposable, async/await |
| Node.js | `quac100.js`, `quac100.d.ts` | N-API bindings, Promises, TypeScript |

## Usage

```bash
# Generate all bindings
quac-bindgen --input ../include --output ../bindings --all

# Generate specific language
quac-bindgen --input ../include --output ../bindings/python --lang python

# Generate with custom options
quac-bindgen --input ../include --output ../bindings/rust \
    --lang rust \
    --prefix quac_ \
    --async \
    --doc-format rustdoc
```

## Command Line Options

```
quac-bindgen [OPTIONS]

Input/Output:
  -i, --input <PATH>      Input directory containing C headers
  -o, --output <PATH>     Output directory for generated bindings
  -H, --header <FILE>     Specific header file to process (can repeat)

Language Selection:
  -l, --lang <LANG>       Target language (python|rust|go|java|csharp|nodejs)
  -a, --all               Generate bindings for all languages

Generation Options:
  -p, --prefix <PREFIX>   Function prefix to strip (default: quac_)
  -n, --namespace <NS>    Namespace/module name (default: quac100)
  --async                 Generate async/await wrappers where applicable
  --no-doc                Skip documentation generation
  --doc-format <FMT>      Documentation format (doxygen|rustdoc|sphinx|javadoc)

Output Control:
  --dry-run               Show what would be generated without writing
  --force                 Overwrite existing files
  -v, --verbose           Verbose output
  -q, --quiet             Suppress non-error output

Misc:
  --version               Show version information
  -h, --help              Show this help message
```

## Configuration File

Create `bindgen.toml` for persistent settings:

```toml
[general]
input = "../include"
output = "../bindings"
prefix = "quac_"
namespace = "quac100"

[python]
enabled = true
async = true
type_hints = true
output = "python/quac100"

[rust]
enabled = true
unsafe_ffi = false
derive = ["Debug", "Clone"]
output = "rust/src"

[go]
enabled = true
package = "quac100"
output = "go/quac100"

[java]
enabled = true
package = "com.dyber.quac100"
output = "java/src/main/java/com/dyber/quac100"

[csharp]
enabled = true
namespace = "Dyber.QUAC100"
output = "csharp/QUAC100"

[nodejs]
enabled = true
typescript = true
output = "nodejs/lib"
```

## Type Mappings

### Primitive Types

| C Type | Python | Rust | Go | Java | C# | Node.js |
|--------|--------|------|-----|------|-----|---------|
| `uint8_t` | `int` | `u8` | `uint8` | `byte` | `byte` | `number` |
| `uint16_t` | `int` | `u16` | `uint16` | `short` | `ushort` | `number` |
| `uint32_t` | `int` | `u32` | `uint32` | `int` | `uint` | `number` |
| `uint64_t` | `int` | `u64` | `uint64` | `long` | `ulong` | `bigint` |
| `int32_t` | `int` | `i32` | `int32` | `int` | `int` | `number` |
| `size_t` | `int` | `usize` | `uintptr` | `long` | `UIntPtr` | `number` |
| `bool` | `bool` | `bool` | `bool` | `boolean` | `bool` | `boolean` |
| `char*` | `str` | `&str` | `string` | `String` | `string` | `string` |
| `void*` | `Any` | `*mut c_void` | `unsafe.Pointer` | `long` | `IntPtr` | `Buffer` |

### SDK Types

| C Type | Python | Rust | Go | Java | C# |
|--------|--------|------|-----|------|-----|
| `quac_result_t` | `QUACError` | `Result<T, Error>` | `error` | `QUACException` | `QUACException` |
| `quac_context_t` | `Context` | `Context` | `Context` | `Context` | `Context` |
| `quac_device_t` | `Device` | `Device` | `Device` | `Device` | `Device` |
| `quac_kem_algorithm_t` | `KEMAlgorithm` | `KEMAlgorithm` | `KEMAlgorithm` | `KEMAlgorithm` | `KEMAlgorithm` |

## Architecture

```
bindgen/
├── src/
│   ├── main.c              # Entry point, argument parsing
│   ├── parser.c            # C header parser
│   ├── parser.h
│   ├── types.c             # Type system and mappings
│   ├── types.h
│   ├── generator.c         # Base generator framework
│   ├── generator.h
│   ├── gen_python.c        # Python generator
│   ├── gen_rust.c          # Rust generator
│   ├── gen_go.c            # Go generator
│   ├── gen_java.c          # Java generator
│   ├── gen_csharp.c        # C# generator
│   └── gen_nodejs.c        # Node.js generator
├── templates/              # Output templates (optional)
├── tests/
│   └── test_parser.c
├── CMakeLists.txt
└── README.md
```

## Building

```bash
cd tools/bindgen
mkdir build && cd build
cmake ..
make
```

## Example Output

### Python

```python
from quac100 import Context, Device, KEMAlgorithm

async with Context() as ctx:
    device = ctx.open_device(0)
    pk, sk = await device.kem_keygen(KEMAlgorithm.ML_KEM_768)
    ct, ss = await device.kem_encaps(pk)
```

### Rust

```rust
use quac100::{Context, KEMAlgorithm};

let ctx = Context::new()?;
let device = ctx.open_device(0)?;
let (pk, sk) = device.kem_keygen(KEMAlgorithm::MlKem768)?;
let (ct, ss) = device.kem_encaps(&pk)?;
```

### Go

```go
ctx, err := quac100.NewContext()
if err != nil { return err }
defer ctx.Close()

device, err := ctx.OpenDevice(0)
pk, sk, err := device.KEMKeygen(quac100.MLKem768)
ct, ss, err := device.KEMEncaps(pk)
```

## License

Copyright 2025 Dyber, Inc. All Rights Reserved.
Proprietary and confidential.