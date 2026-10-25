"""Read-only inspection of the observed UPX ELF32/LZMA container.

Format reference: UPX v3.96 p_lx_elf.cpp PackLinuxElf32::unpack and
compress_lzma.cpp. This is a bounded partial decoder, not an unpacker: encrypted
blocks and filtered code are never promoted to native input. No vendor code runs.
"""
from __future__ import annotations

import lzma
import struct

from firmware import sha256

MAGIC = 0x22552255
MAX_UNPACKED = 16 * 1024 * 1024


def elf_headers(data, partial=False):
    if len(data) < 52:
        raise ValueError('Truncated ELF header')
    h = struct.unpack_from('<16sHHIIIIIHHHHHH', data)
    if (h[0][:7] != b'\x7fELF\x01\x01\x01' or h[1:4] != (2, 40, 1)
            or h[5] != 52 or h[8:10] != (52, 32) or not 1 <= h[10] <= 16):
        raise ValueError('Unsupported packed/original ELF32 ARM headers')
    end = 52 + 32 * h[10]
    if end > len(data) or (partial and end != len(data)):
        raise ValueError('Truncated or noncanonical ELF program table')
    ph = [struct.unpack_from('<8I', data, 52 + i * 32) for i in range(h[10])]
    return h, ph, end


def decode_lzma(source, size):
    """UPX's two-byte properties and size-delimited raw LZMA1 (no EOS needed)."""
    if len(source) < 3 or not 0 < size <= MAX_UNPACKED:
        raise ValueError('Invalid LZMA block bounds')
    pb, lp, lc = source[0] & 7, source[1] >> 4, source[1] & 15
    if pb >= 5 or lp >= 5 or lc >= 9 or source[0] >> 3 != lc + lp:
        raise ValueError('Invalid UPX LZMA properties; encrypted or unsupported block')
    # liblzma supports lc+lp <= 4. Do not mislabel a valid unsupported stream.
    if lc + lp > 4:
        raise ValueError('LZMA properties exceed host liblzma support')
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[dict(
        id=lzma.FILTER_LZMA1, dict_size=max(4096, size), pb=pb, lp=lp, lc=lc)])
    try:
        # UPX passes an explicit output size to LzmaDecode; padding may decode
        # further without an end marker. Do not request a speculative extra byte.
        result = decoder.decompress(source[2:], max_length=size)
    except lzma.LZMAError as error:
        raise ValueError(f'LZMA decode failed: {error}') from error
    if len(result) != size or decoder.unused_data:
        raise ValueError('LZMA output length or trailing data differs')
    return result


def inspect_packed(data):
    """Return identities and partial evidence; never an executable or permission."""
    h, ph, table_end = elf_headers(data)
    if h[6] or h[12] or len(ph) != 3 or ph[0][0:3] != (1, 0, 0x10000):
        raise ValueError('Unsupported packed ELF layout')
    if ph[0][6] != 5 or ph[1][0] != 1 or ph[1][6] != 6 or ph[1][4] != 0:
        raise ValueError('Unsupported packed LOAD layout')
    if ph[0][4] > len(data) or ph[0][4] != ph[0][5]:
        raise ValueError('Invalid packed LOAD bounds')
    if table_end + 24 > len(data):
        raise ValueError('Truncated packing metadata')
    checksum, magic, loader_size, version, fmt = struct.unpack_from('<IIHBB', data, table_end)
    progid, original_size, block_size = struct.unpack_from('<III', data, table_end + 12)
    if (magic != MAGIC or version != 13 or fmt != 23 or progid != 0
            or not len(data) <= original_size <= MAX_UNPACKED or block_size != original_size):
        raise ValueError('Unsupported UPX metadata')
    cursor = table_end + 24
    blocks = []

    def block(role, size=None, destination=None):
        nonlocal cursor
        if cursor + 12 > len(data):
            raise ValueError('Truncated block header')
        unc, cpr, method, ftid, cto, unused = struct.unpack_from('<IIBBBB', data, cursor)
        if (not 0 < cpr <= unc <= original_size or cursor + 12 + cpr > len(data)
                or unused or method != 14 or ftid not in (0, 0x50) or cto
                or (size is not None and unc != size)):
            raise ValueError('Unsupported block extent/method/filter')
        source = data[cursor + 12:cursor + 12 + cpr]
        evidence = dict(role=role, header_offset=cursor, payload_offset=cursor + 12,
                        compressed_bytes=cpr, uncompressed_bytes=unc, method=method,
                        filter_id=ftid, destination_file_offset=destination,
                        compressed_sha256=sha256(source), prefix_hex=source[:16].hex(),
                        hardware_upx_decrypt_predicate=cpr >= 8192 and source[0] & 7 >= 5)
        result = None
        try:
            result = source if cpr == unc else decode_lzma(source, unc)
            evidence.update(decoded_bytes=len(result), decoded_sha256=sha256(result),
                            status='host-decoded; filter not reversed' if ftid else 'host-decoded partial extent')
        except ValueError as error:
            evidence.update(status='not decoded', reason=str(error))
        blocks.append(evidence)
        cursor += 12 + cpr
        return result

    header = block('original ELF/program headers', destination=0)
    if header is None or blocks[0]['filter_id']:
        raise ValueError('Cannot establish original ELF headers')
    original, original_ph, _ = elf_headers(header, partial=True)
    if original[1:4] != h[1:4] or original[7] != h[7]:
        raise ValueError('Original/packed ELF identity fields differ')
    if original[6] + original[11] * original[12] != original_size:
        raise ValueError('Original section table/file size differs')
    loads = [p for p in original_ph if p[0] == 1]
    if len(loads) != 2 or loads[0][1] != 0 or [p[6] for p in loads] != [5, 6]:
        raise ValueError('Unsupported original LOAD ordering')
    for index, p in enumerate(loads):
        if p[4] > p[5] or p[1] + p[4] > original_size:
            raise ValueError('Original LOAD out of bounds')
        if index and loads[index - 1][1] + loads[index - 1][4] > p[1]:
            raise ValueError('Original LOAD file ranges overlap')
        skip = len(header) if index == 0 else 0
        block(f'LOAD {index} remainder', p[4] - skip, p[1] + skip)
    # This observed ET_EXEC layout places the loader between LOAD and gap data.
    loader_start = (cursor + 3) & ~3
    if (any(data[cursor:loader_start]) or h[4] != ph[0][2] + loader_start + 12
            or loader_size < 16 or loader_start + loader_size > len(data)):
        raise ValueError('Unsupported embedded loader placement')
    loader = data[loader_start:loader_start + loader_size]
    cursor = loader_start + loader_size
    for index, p in enumerate(loads):
        end = p[1] + p[4]
        next_offset = loads[index + 1][1] if index + 1 < len(loads) else original_size
        if next_offset > end:
            block(f'file gap after LOAD {index}', next_offset - end, end)
    if cursor + 12 > len(data) or struct.unpack_from('<III', data, cursor) != (0, MAGIC, 0):
        raise ValueError('Missing canonical packed end marker')
    return dict(schema='c10-packed-structure-v1', packed_sha256=sha256(data), packed_bytes=len(data),
                format='observed obfuscated UPX ELF32 ARM/LZMA', original_file_bytes=original_size,
                original_header_sha256=sha256(header), original_entry=original[4],
                original_program_headers=[list(p) for p in original_ph], blocks=blocks,
                loader=dict(file_offset=loader_start, bytes=loader_size, sha256=sha256(loader),
                            entry_va=h[4], checksum_field=checksum,
                            checksum_verified=False),
                end_marker_offset=cursor, complete_unpacked_sha256=None,
                complete_native_input=False, patchable=False, evidence_level='host partial decoding',
                limitations=['No complete ELF reconstructed; filtered code and encrypted blocks unresolved',
                             'Checksums and hardware decryption have not been verified',
                             'Hardware predicate is a source-patch condition, not cryptographic proof'])
