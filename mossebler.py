import binascii
import argparse
import os
from capstone import *

# Mapping of supported architectures and modes
ARCHITECTURES = {
    'x86': CS_ARCH_X86,
    'arm': CS_ARCH_ARM,
    'arm64': CS_ARCH_ARM64,
    'mips': CS_ARCH_MIPS,
    'ppc': CS_ARCH_PPC,
    'sparc': CS_ARCH_SPARC,
    'sysz': CS_ARCH_SYSZ,
    'xcore': CS_ARCH_XCORE,
    'm68k': CS_ARCH_M68K,
    'tms320c64x': CS_ARCH_TMS320C64X,
}

MODES = {
    '16': CS_MODE_16,
    '32': CS_MODE_32,
    '64': CS_MODE_64,
}

def validate_arch_mode(arch, mode):
    """Ensure the chosen architecture and mode are compatible."""
    if arch == CS_ARCH_X86 and mode not in [CS_MODE_16, CS_MODE_32, CS_MODE_64]:
        print("Error: Invalid mode for x86 architecture. Choose 16, 32, or 64.")
        exit(1)
    if arch != CS_ARCH_X86 and mode != CS_MODE_32:
        print("Warning: Non-x86 architectures typically use 32-bit mode. Proceeding with the given mode.")

def disassemble_code(hex_bytes, arch, mode, base_address):
    """Disassembles the provided hex bytes using Capstone."""
    md = Cs(arch, mode)
    print(f"\n[+] Disassembling with architecture: {arch}, mode: {mode}, base address: {hex(base_address)}")
    for instruction in md.disasm(hex_bytes, base_address):
        print(f"0x{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}")

def read_ascii_file(file_path):
    """Reads shellcode from an ASCII file and converts it to bytes after cleaning."""
    try:
        with open(file_path, 'r') as f:
            ascii_content = f.read().strip()
            # Clean up content: remove newlines, spaces, and quotes
            cleaned_content = ascii_content.replace('\n', '').replace('\r', '').replace(' ', '').replace("'", '').replace('"', '')
            return binascii.unhexlify(cleaned_content.replace("\\x", ""))
    except (binascii.Error, ValueError) as e:
        print(f"Error: Invalid hex content in the ASCII file: {e}")
        exit(1)
    except Exception as e:
        print(f"Error reading ASCII file: {e}")
        exit(1)

def read_binary_file(file_path):
    """Reads shellcode directly from a binary file."""
    try:
        with open(file_path, 'rb') as f:
            return f.read()
    except Exception as e:
        print(f"Error reading binary file: {e}")
        exit(1)

def validate_file_path(file_path, file_type):
    """Validates that a given file path exists."""
    if not os.path.isfile(file_path):
        print(f"Error: The {file_type} file '{file_path}' does not exist.")
        exit(1)

def validate_input_source(args):
    """Ensures only one input source is provided."""
    if sum([bool(args.hex_code), bool(args.ascii_file), bool(args.binary_file)]) != 1:
        print("Error: You must provide exactly one input source (hex string, --ascii-file, or --binary-file).")
        exit(1)

def handle_hex_string(hex_string):
    """Processes the hex string into byte format."""
    try:
        return binascii.unhexlify(hex_string.replace("\\x", ""))
    except binascii.Error as e:
        print(f"Error: Invalid hex string provided: {e}")
        exit(1)

def parse_arguments():
    """Parses the command-line arguments."""
    parser = argparse.ArgumentParser(
        prog='Mossembler',  # Tool name
        description='Mossembler is a shellcode disassembler written by Moustafa Saleh',
        epilog='Thank you for using Mossembler! Feel free to extend and share!',
    )

    parser.add_argument(
        '-a', '--arch',
        choices=ARCHITECTURES.keys(),
        default='x86',
        help='Architecture to disassemble (default: x86)'
    )

    parser.add_argument(
        '-m', '--mode',
        choices=MODES.keys(),
        default='32',
        help='Mode for the chosen architecture (default: 32-bit)'
    )

    parser.add_argument(
        '-b', '--base-address',
        type=lambda x: int(x, 0),  # Accepts decimal or hexadecimal (e.g., 0x1000)
        default=0x1000,
        help='Base address for the disassembly (default: 0x1000)'
    )

    parser.add_argument(
        '-x', '--hex-code',
        help='Hex code string to disassemble (e.g. "\\x90\\x90\\xCC")'
    )

    parser.add_argument(
        '-A', '--ascii-file',
        help="Read hex string from an ASCII file (e.g., '\\x90\\x90')."
    )

    parser.add_argument(
        '-B', '--binary-file',
        help="Read shellcode from a binary file."
    )

    return parser.parse_args()

def main():
    # Parse command line arguments
    args = parse_arguments()

    # Validate input source (ensure only one input source is provided)
    validate_input_source(args)

    # Get the architecture and mode from the arguments
    arch = ARCHITECTURES[args.arch]
    mode = MODES[args.mode]

    # Validate compatibility of architecture and mode
    validate_arch_mode(arch, mode)

    # Determine input source (command line, ASCII file, or binary file)
    hex_bytes = None
    if args.ascii_file:
        validate_file_path(args.ascii_file, "ASCII")
        hex_bytes = read_ascii_file(args.ascii_file)
    elif args.binary_file:
        validate_file_path(args.binary_file, "binary")
        hex_bytes = read_binary_file(args.binary_file)
    elif args.hex_code:
        hex_bytes = handle_hex_string(args.hex_code)
    else:
        print("Error: No input provided. Use --hex-code, --ascii-file, or --binary-file.")
        exit(1)

    # Disassemble the provided hex string or file content with the given base address
    disassemble_code(hex_bytes, arch, mode, args.base_address)

if __name__ == "__main__":
    main()
