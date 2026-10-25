"""Reproducible host decoding of the observed packed ARM driver.

The optional kernel snapshot is caller-supplied local evidence. Its exact recipe
is tied to a separately audited ioctl implementation, not a stock-image version.
No keys, kernel bytes, vendor executables or captures are bundled. Decoding grants
no patch authority. UPX checksums are enforced, unlike the legacy hardware tool.
"""
from __future__ import annotations

import struct
import zlib
import sys
import _lzma
from pathlib import Path
import cryptography

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from firmware import sha256
from generic_analysis import Driver
from generic_packing import MAGIC, decode_lzma, inspect_packed

KERNEL_SHA = '8ab82dbbc95b2a5bb9d7dad26b100aa476a4496ab336f8930be98b660cc9965c'
KERNEL_BASE = 0x80008000
KEY_LITERAL, IV_LITERAL = 0x802946bc, 0x802946c0


def kernel_material(kernel):
    if len(kernel) != 8388608 or sha256(kernel) != KERNEL_SHA:
        raise ValueError('Unsupported kernel evidence; ioctl/key/IV derivation not audited')
    values, provenance = [], []
    for literal in (KEY_LITERAL, IV_LITERAL):
        address = struct.unpack_from('<I', kernel, literal - KERNEL_BASE)[0]
        offset = address - KERNEL_BASE
        if not 0 <= offset <= len(kernel) - 16:
            raise ValueError('Kernel material reference is not snapshot-backed')
        data = kernel[offset:offset + 16]
        values.append(data)
        provenance.append(dict(literal_va=literal, data_va=address, bytes=16, sha256=sha256(data)))
    return values[0], values[1], dict(kernel_sha256=sha256(kernel), kernel_bytes=len(kernel),
                                    mapping_base=KERNEL_BASE, key=provenance[0], iv=provenance[1],
                                    ioctl=0xc00c6206, recipe='AES-128-CBC decrypt first 8192 compressed bytes')


def arm_call_filter(data, reverse=True):
    """Interoperable UPX filter50 arithmetic, independently expressed.

Walk aligned words except the final four bytes; for ARM call-tag words adjust
the low 24-bit word-relative operand modulo 2**24. The block base is zero.
The inverse form is used only for round-trip/independent verification.
"""
    if len(data) < 8:
        raise ValueError('ARM filter block is too short')
    out = bytearray(data)
    for index in range(0, len(out) - 4, 4):
        if out[index + 3] & 15 == 11:
            operand = int.from_bytes(out[index:index + 3], 'little')
            delta = index // 4
            operand = operand - delta if reverse else operand + delta
            out[index:index + 3] = (operand & 0xffffff).to_bytes(3, 'little')
    return bytes(out)


def unpack_driver(packed, kernel):
    structure = inspect_packed(packed)
    key, iv, provenance = kernel_material(kernel)
    result = bytearray(structure['original_file_bytes'])
    coverage, evidence = [], []
    compressed_adler = uncompressed_adler = 1
    for block in structure['blocks']:
        start, size = block['payload_offset'], block['compressed_bytes']
        original = packed[start:start + size]
        compressed_adler = zlib.adler32(original, compressed_adler)
        source = original
        decrypted = False
        if block['hardware_upx_decrypt_predicate']:
            if size < 8192:
                raise ValueError('Encrypted block is smaller than supported transform')
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
            source = cipher.update(source[:8192]) + cipher.finalize() + source[8192:]
            decrypted = True
        decoded = source if size == block['uncompressed_bytes'] else decode_lzma(source, block['uncompressed_bytes'])
        if block['filter_id']:
            if block['filter_id'] != 0x50:
                raise ValueError('Unsupported native code filter')
            decoded = arm_call_filter(decoded)
        uncompressed_adler = zlib.adler32(decoded, uncompressed_adler)
        dest = block['destination_file_offset']
        if dest < 0 or dest + len(decoded) > len(result):
            raise ValueError('Decoded extent exceeds original file')
        coverage.append((dest, dest + len(decoded)))
        result[dest:dest + len(decoded)] = decoded
        evidence.append(dict(role=block['role'], packed_file_offset=start, compressed_bytes=size,
                             original_compressed_sha256=sha256(original), decrypted_prefix_bytes=8192 if decrypted else 0,
                             plaintext_compressed_sha256=sha256(source), filter_id=block['filter_id'],
                             destination_file_offset=dest, decoded_bytes=len(decoded), decoded_sha256=sha256(decoded)))
    end = 0
    for lo, hi in sorted(coverage):
        if lo != end or hi <= lo:
            raise ValueError('Decoded extents leave gaps or overlap')
        end = hi
    if end != len(result):
        raise ValueError('Decoded file coverage is incomplete')
    # The observed trailer is two pad bytes, a 32-byte PackHeader, then an
    # overlay pointer. Require its exact placement rather than scanning magic.
    footer_offset = structure['end_marker_offset'] + 14
    if footer_offset + 36 != len(packed):
        raise ValueError('Unsupported packed footer extent')
    if (packed[footer_offset - 2:footer_offset] != bytes(2) or struct.unpack_from('<I', packed, len(packed) - 4)[0]
            != structure['blocks'][0]['header_offset'] - 12):
        raise ValueError('Packed padding or overlay pointer differs')
    footer = packed[footer_offset:footer_offset + 32]
    if footer[:8] != struct.pack('<I4B', MAGIC, 13, 23, 14, 8):
        raise ValueError('Unsupported packed footer identity')
    if sum(footer[4:31]) % 251 != footer[31]:
        raise ValueError('Packed header checksum mismatch')
    expected_unc, expected_cpr, last_unc, last_cpr, original_bytes = struct.unpack_from('<5I', footer, 8)
    if (expected_unc != uncompressed_adler or expected_cpr != compressed_adler
            or original_bytes != len(result) or last_unc != structure['blocks'][-1]['uncompressed_bytes']
            or last_cpr != structure['blocks'][-1]['compressed_bytes']):
        raise ValueError('Packed compressed/uncompressed checksum or size mismatch')
    driver = Driver(bytes(result))
    # Validate all file-backed section extents, their allocated mappings and the
    # entry mapping independently of any particular Open/touch detector match.
    driver.offset(driver.elf['e_entry'] & ~1, 2, executable=True)
    for section in driver.elf.iter_sections():
        if section['sh_type'] != 'SHT_NOBITS':
            if section['sh_offset'] + section['sh_size'] > len(result):
                raise ValueError('Decoded ELF section exceeds file')
            if section['sh_flags'] & 2 and section['sh_size'] and driver.offset(
                    section['sh_addr'], section['sh_size']) != section['sh_offset']:
                raise ValueError('Decoded ELF allocated section mapping differs')
    return bytes(result), dict(schema='c10-host-unpack-evidence-v1', method='host AES-CBC/LZMA1/ARM-filter50 reconstruction',
                              decoder_sha256=sha256(Path(__file__).read_bytes()),
                              backend=dict(python=sys.version, cryptography=cryptography.__version__,
                                           lzma_extension_sha256=sha256(Path(_lzma.__file__).read_bytes())),
                              packed_driver_sha256=sha256(packed), unpacked_driver_sha256=sha256(result),
                              unpacked_bytes=len(result), kernel_provenance=provenance, blocks=evidence,
                              checksums=dict(compressed_adler32=compressed_adler, uncompressed_adler32=uncompressed_adler,
                                             ordering='UPX block order; may differ from final file order',
                                             pack_header=True, compressed=True, uncompressed=True),
                              complete_file_coverage=True, elf_structure_checked=True,
                              decoding_reproduced=True, patchable=False, hardware_tested=False,
                              limits='Checksums validate reconstruction, not firmware authenticity or patch compatibility')
