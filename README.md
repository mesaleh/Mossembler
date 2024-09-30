**Mossembler** is a shellcode disassembler written in Python using the Capstone disassembly framework. It helps reverse engineers, security researchers, and developers disassemble shellcodes into human-readable assembly instructions.

---
## Features

- Supports multiple architectures (e.g., x86, ARM, MIPS, PPC, etc.)
- Allows disassembly from:
  - A hex string passed via the command line
  - An ASCII-encoded file with hex codes
  - A binary file containing shellcode
- Option to specify a custom base address for disassembly (default: `0x1000`)
- Supports different modes (16-bit, 32-bit, 64-bit) depending on the chosen architecture
- Clean and user-friendly interface with proper error handling

---

## Installation

### Requirements

- Python 3.x
- Capstone disassembly framework (`capstone`)
- Standard Python libraries like `binascii`, `os`, and `argparse`

Install Capstone with pip:

```bash
pip install capstone
```

---

## Usage

Mossembler provides multiple options for input sources and configurations. You can disassemble shellcode from a hex string, ASCII-encoded files, or binary files.

### Command-line Options

| Option              | Description                                                                                      |
|---------------------|--------------------------------------------------------------------------------------------------|
| `-a, --arch`        | Architecture to disassemble (default: `x86`). Supported values: `x86`, `arm`, `arm64`, etc.       |
| `-m, --mode`        | Mode for the chosen architecture (default: `32`). Supported values: `16`, `32`, `64`.             |
| `-b, --base-address`| Base address for the disassembly (default: `0x1000`). You can specify it in decimal or hexadecimal.|
| `-x, --hex-code`    | Hex code string to disassemble (e.g., `\\x90\\x90\\xCC`).                                         |
| `-A, --ascii-file`  | Read hex string from an ASCII file (e.g., `\\x90\\x90`).                                          |
| `-B, --binary-file` | Read shellcode from a binary file.                                                                |
| `-h, --help`        | Display the help message and usage instructions.                                                  |

---

## Example Usages

### 1. Disassemble a Hex String:
```bash
$ python mossembler.py -x "\x90\x90\xCC"
```
Output:
```
[+] Disassembling with architecture: x86, mode: 32, base address: 0x1000
0x1000:    nop
0x1001:    nop
0x1002:    int3
```

### 2. Disassemble from an ASCII File:
```bash
$ python mossembler.py -A shellcode.txt
```
> **Note**: The tool automatically cleans the ASCII file by removing newlines, spaces, and quotes before processing.

### 3. Disassemble from a Binary File with a Custom Base Address:
```bash
$ python mossembler.py -B shellcode.bin -b 0x2000
```

### 4. Disassemble with Different Architecture and Mode:
```bash
$ python mossembler.py -x "\x90\x90\xCC" -a arm -m 32
```

---

## Supported Architectures and Modes

- **Architectures**:
  - `x86`
  - `arm`
  - `arm64`
  - `mips`
  - `ppc`
  - `sparc`
  - `sysz`
  - `xcore`
  - `m68k`
  - `tms320c64x`
  
- **Modes**:
  - `16` (16-bit)
  - `32` (32-bit)
  - `64` (64-bit)

---

## Input Sources

### Hex String (`-x` or `--hex-code`):
You can directly provide a hex string to disassemble:
```bash
$ python mossembler.py -x "\x90\x90\xCC"
```

### ASCII File (`-A` or `--ascii-file`):
You can provide an ASCII file containing hex code, such as:
```txt
\x90\x90\xCC
```
Example:
```bash
$ python mossembler.py -A shellcode.txt
```

### Binary File (`-B` or `--binary-file`):
Provide a binary file that contains shellcode:
```bash
$ python mossembler.py -B shellcode.bin
```

---

## Custom Base Address

The base address of disassembly can be customized with the `-b` or `--base-address` option. The default base address is `0x1000`, but you can change it to anything.

Example:
```bash
$ python mossembler.py -x "\x90\x90\xCC" -b 0x4000
```

---

## Error Handling and Validation

- **Input Validation**: Only one input source is allowed at a time (either hex string, ASCII file, or binary file).
- **File Validation**: The tool checks if the provided file paths are valid before proceeding.
- **Hex String Cleanup**: The ASCII file input is cleaned up by removing newlines, spaces, and quotes, ensuring proper formatting before disassembly.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- **Capstone Framework** - [Capstone](https://www.capstone-engine.org/) is used for the disassembly in this project.

---
