#!/usr/bin/env python3
"""
Convert WIT (WebAssembly Interface Type) definitions to WAI format.

Key transformations:
1. Remove package declaration
2. Flatten interfaces - prefix function names with interface name
3. Convert `result<T, E>` to `expected<T, E>`
4. Convert `_` to `unit` in result types
5. Remove `use` statements
6. Keep types at the top level
"""

import re
import sys
from pathlib import Path


def convert_result_to_expected(line: str) -> str:
    """Convert result<T, E> to expected<T, E> and result<_, E> to expected<unit, E>"""
    # Replace result<_, with expected<unit,
    line = re.sub(r'\bresult<_,', 'expected<unit,', line)
    # Replace result< with expected<
    line = re.sub(r'\bresult<', 'expected<', line)
    return line


def parse_wit_file(content: str) -> dict:
    """Parse WIT file and extract interfaces, types, and functions."""
    result = {
        'types': [],      # Top-level type definitions
        'interfaces': {}, # interface_name -> list of (comment, func_def)
    }

    lines = content.split('\n')
    current_interface = None
    current_comment_lines = []
    in_types_interface = False
    brace_depth = 0

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Skip package declaration
        if stripped.startswith('package '):
            i += 1
            continue

        # Track brace depth
        brace_depth += stripped.count('{') - stripped.count('}')

        # Detect interface start
        interface_match = re.match(r'^interface\s+([\w-]+)\s*\{', stripped)
        if interface_match:
            current_interface = interface_match.group(1)
            if current_interface == 'types':
                in_types_interface = True
            else:
                in_types_interface = False
                result['interfaces'][current_interface] = []
            current_comment_lines = []
            i += 1
            continue

        # Detect interface end
        if stripped == '}' and current_interface and brace_depth == 0:
            current_interface = None
            in_types_interface = False
            current_comment_lines = []
            i += 1
            continue

        # Skip 'use' statements
        if stripped.startswith('use '):
            i += 1
            continue

        # Skip world declaration
        if stripped.startswith('world '):
            # Skip until closing brace
            while i < len(lines) and not lines[i].strip() == '}':
                i += 1
            i += 1
            continue

        # Collect doc comments
        if stripped.startswith('///'):
            current_comment_lines.append(stripped)
            i += 1
            continue

        # Regular comments (section headers)
        if stripped.startswith('//'):
            current_comment_lines.append(stripped)
            i += 1
            continue

        # In types interface - collect type definitions
        if in_types_interface and stripped:
            # Collect multi-line type definitions (variant, record)
            if stripped.startswith('variant ') or stripped.startswith('record '):
                type_lines = current_comment_lines + [stripped]  # Use stripped to remove indentation
                current_comment_lines = []
                # Collect until closing brace at same level
                type_brace_depth = stripped.count('{') - stripped.count('}')
                i += 1
                while i < len(lines) and type_brace_depth > 0:
                    type_lines.append(lines[i].strip())  # Strip indentation
                    type_brace_depth += lines[i].count('{') - lines[i].count('}')
                    i += 1
                # Re-indent properly
                result['types'].append(reindent_type(type_lines))
                continue

        # In a regular interface - collect function definitions
        if current_interface and not in_types_interface and stripped:
            # Function definition
            func_match = re.match(r'^(%?\w[\w-]*)\s*:\s*func\s*\(', stripped)
            if func_match:
                func_lines = current_comment_lines + [stripped]  # Use stripped
                current_comment_lines = []
                # Check if function continues on next lines
                paren_depth = stripped.count('(') - stripped.count(')')
                i += 1
                while i < len(lines) and paren_depth > 0:
                    func_lines.append(lines[i].strip())
                    paren_depth += lines[i].count('(') - lines[i].count(')')
                    i += 1
                result['interfaces'][current_interface].append('\n'.join(func_lines))
                continue

        current_comment_lines = []
        i += 1

    return result


def reindent_type(lines: list) -> str:
    """Re-indent a type definition properly."""
    result = []
    indent = 0
    for line in lines:
        if line.startswith('}'):
            indent -= 1
        result.append('    ' * indent + line)
        if line.endswith('{'):
            indent += 1
    return '\n'.join(result)


def convert_function(interface_name: str, func_def: str) -> str:
    """Convert a WIT function definition to WAI format."""
    lines = func_def.split('\n')
    result_lines = []

    for line in lines:
        stripped = line.strip()

        # Pass through comments
        if stripped.startswith('//'):
            result_lines.append(stripped)
            continue

        # Convert function definition
        func_match = re.match(r'^(%?\w[\w-]*)\s*:\s*func\s*\((.*)', stripped)
        if func_match:
            func_name = func_match.group(1)
            rest = func_match.group(2)

            # Handle % prefix (escaped keywords like %final)
            if func_name.startswith('%'):
                func_name = func_name[1:]  # Remove % prefix

            # Build prefixed name, avoiding redundancy
            prefixed_name = build_prefixed_name(interface_name, func_name)

            # Reconstruct the function
            new_line = f"{prefixed_name}: func({rest}"

            # Convert result to expected
            new_line = convert_result_to_expected(new_line)

            # Remove trailing semicolon (WAI doesn't use semicolons)
            new_line = new_line.rstrip(';')

            result_lines.append(new_line)
            continue

        # Convert result to expected for continuation lines
        converted = convert_result_to_expected(stripped)
        # Remove trailing semicolon (WAI doesn't use semicolons)
        converted = converted.rstrip(';')
        result_lines.append(converted)

    return '\n'.join(result_lines)


def build_prefixed_name(interface_name: str, func_name: str) -> str:
    """Build a prefixed function name for WAI.

    The naming convention follows the pattern: interface-name-function-name
    except for the 'core' interface which uses unprefixed names.

    This matches the naming expected by wai_component.rs.
    """
    # Special case: core interface uses unprefixed names
    if interface_name == 'core':
        return func_name

    # Special case: if function name already starts with interface name followed by dash
    # e.g., random.random-bytes -> random-bytes (avoid random-random-bytes)
    if func_name.startswith(interface_name + '-'):
        return func_name

    # Default: prefix with interface name
    # e.g., sign.bytes -> sign-bytes
    # e.g., auth.auth -> auth-auth
    # e.g., seal.seal -> seal-seal (but seal has seal -> seal-seal, open -> seal-open)
    return f"{interface_name}-{func_name}"


def generate_section_header(interface_name: str, description: str = "") -> str:
    """Generate a section header comment."""
    header = f"// {'=' * 76}\n"
    header += f"// {interface_name}"
    if description:
        header += f" - {description}"
    header += f"\n// {'=' * 76}\n"
    return header


# Interface descriptions from WIT comments
INTERFACE_DESCRIPTIONS = {
    'core': 'Library initialization and version information',
    'random': 'Secure random number generation',
    'random-extended': 'Extended random functions',
    'secretbox': 'Secret-key authenticated encryption (XSalsa20-Poly1305)',
    'secretbox-xchacha20poly1305': 'Secret-key encryption with XChaCha20-Poly1305',
    'crypto-box': 'Public-key authenticated encryption (X25519-XSalsa20-Poly1305)',
    'crypto-box-xchacha20poly1305': 'Public-key encryption with X25519-XChaCha20-Poly1305',
    'seal': 'Anonymous public-key encryption (sealed boxes)',
    'sign': 'Public-key signatures (Ed25519)',
    'generichash': 'Generic hashing (BLAKE2b)',
    'generichash-state': 'Streaming generic hash (BLAKE2b)',
    'sha256': 'SHA-256 hashing',
    'sha256-state': 'Streaming SHA-256 hash',
    'sha512': 'SHA-512 hashing',
    'sha512-state': 'Streaming SHA-512 hash',
    'auth': 'Secret-key authentication (HMAC-SHA512-256)',
    'auth-state': 'Streaming authentication (HMAC-SHA512-256)',
    'auth-hmacsha256': 'HMAC-SHA256 authentication',
    'auth-hmacsha512': 'HMAC-SHA512 authentication',
    'auth-hmacsha512256': 'HMAC-SHA-512-256 authentication',
    'aead-xchacha20poly1305': 'AEAD encryption (XChaCha20-Poly1305-IETF)',
    'aead-chacha20poly1305-ietf': 'AEAD encryption (ChaCha20-Poly1305-IETF)',
    'aead-chacha20poly1305': 'AEAD encryption (original ChaCha20-Poly1305)',
    'aead-aegis128l': 'AEAD encryption (AEGIS-128L)',
    'aead-aegis256': 'AEAD encryption (AEGIS-256)',
    'aead-aes256gcm': 'AEAD encryption (AES-256-GCM)',
    'pwhash': 'Password hashing (Argon2)',
    'pwhash-scrypt': 'Password hashing (scrypt)',
    'kdf': 'Key derivation (BLAKE2b-based)',
    'kdf-hkdf-sha256': 'HKDF-SHA256',
    'kdf-hkdf-sha512': 'HKDF-SHA512',
    'kx': 'Key exchange (X25519 + BLAKE2b)',
    'scalarmult': 'Scalar multiplication on Curve25519',
    'scalarmult-ed25519': 'Scalar multiplication on Ed25519',
    'scalarmult-ristretto255': 'Scalar multiplication on Ristretto255',
    'utils': 'Secure memory utilities',
    'verify': 'Constant-time byte comparison',
    'shorthash': 'Short-input hashing (SipHash-2-4)',
    'onetimeauth': 'One-time authentication (Poly1305)',
    'onetimeauth-state': 'Streaming one-time authentication (Poly1305)',
    'secret-stream': 'Secret stream encryption (XChaCha20-Poly1305 streaming)',
    'ristretto255': 'Ristretto255 group operations',
    'ed25519': 'Ed25519 group operations (low-level)',
    'cipher-xsalsa20': 'XSalsa20 stream cipher',
    'cipher-xchacha20': 'XChaCha20 stream cipher',
    'cipher-salsa20': 'Salsa20 stream cipher',
    'cipher-chacha20': 'ChaCha20 stream cipher',
    'cipher-chacha20-ietf': 'ChaCha20-IETF stream cipher (96-bit nonce)',
    'xof-shake128': 'SHAKE128 extendable output function (XOF)',
    'xof-shake256': 'SHAKE256 extendable output function (XOF)',
    'xof-turboshake128': 'TurboSHAKE128 extendable output function',
    'xof-turboshake256': 'TurboSHAKE256 extendable output function',
    'ipcrypt': 'IP address encryption',
}


def generate_wai(parsed: dict) -> str:
    """Generate WAI output from parsed WIT data."""
    output = []

    # Header
    output.append("// libsodium cryptographic library - WAI interface for Wasmer")
    output.append("// This provides safe wrappers around libsodium's functionality")
    output.append("// Auto-generated from WIT definitions")
    output.append("")

    # Types section
    for type_def in parsed['types']:
        output.append(type_def)
        output.append("")

    # Interfaces section
    for interface_name, functions in parsed['interfaces'].items():
        if not functions:
            continue

        # Section header
        desc = INTERFACE_DESCRIPTIONS.get(interface_name, '')
        output.append(generate_section_header(interface_name.title().replace('-', ' '), desc))

        # Convert each function
        for func_def in functions:
            converted = convert_function(interface_name, func_def)
            output.append(converted)
            output.append("")

    return '\n'.join(output)


def main():
    wit_path = Path(__file__).parent / 'wit' / 'libsodium.wit'
    wai_path = Path(__file__).parent / 'wai' / 'libsodium.wai'

    print(f"Reading WIT from: {wit_path}")
    content = wit_path.read_text()

    print("Parsing WIT file...")
    parsed = parse_wit_file(content)

    print(f"Found {len(parsed['types'])} type definitions")
    print(f"Found {len(parsed['interfaces'])} interfaces:")
    for name, funcs in parsed['interfaces'].items():
        print(f"  - {name}: {len(funcs)} functions")

    print("\nGenerating WAI output...")
    wai_output = generate_wai(parsed)

    print(f"Writing WAI to: {wai_path}")
    wai_path.write_text(wai_output)

    print("Done!")


if __name__ == '__main__':
    main()
