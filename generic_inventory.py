"""Bounded, read-only inventory for unfamiliar A15W update archives.

Kept separate from the stable, hash-pinned reader. Never extract archive paths.
"""
from __future__ import annotations

import gzip
import io
import posixpath
import re
import tarfile

from firmware import crypt, sha256

MAX_IMAGE = 64 * 1024 * 1024
MAX_TAR = 128 * 1024 * 1024
MAX_MEMBERS = 4096
REQUIRED = (
    'etc/box_product_type', 'etc/software_version',
    'usr/sbin/ARMadb-driver', 'usr/sbin/ARMAndroidAuto',
    'script/start_main_service.sh', 'script/phone_link_deamon.sh',
)
# These vendor aliases are metadata only; never follow them when reading inputs.
ALIASES = {
    'usr/lib/libcrypto.so': 'libcrypto.so.1.1',
    'usr/lib/libssl.so': 'libssl.so.1.1',
}


def canonical(name):
    if name in ('.', './'):
        return '.'
    if name.startswith('./'):
        name = name[2:]
    name = name.rstrip('/')
    if (not name or '\\' in name or ':' in name or name.startswith('/')
            or any(ord(c) < 32 or ord(c) > 126 for c in name)
            or any(p in ('', '.', '..') for p in name.split('/'))):
        raise ValueError(f'Unsafe archive path: {name!r}')
    return name


def inventory(image):
    if not 0 < len(image) <= MAX_IMAGE:
        raise ValueError('Update image exceeds supported size limit or is empty')
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(crypt(image, True))) as stream:
            plain = stream.read(MAX_TAR + 1)
        if len(plain) > MAX_TAR:
            raise ValueError('Decompressed update exceeds supported size limit')
        with tarfile.open(fileobj=io.BytesIO(plain), mode='r:') as archive:
            members, files, records = {}, {}, {}
            total = 0
            for member in archive:
                if len(members) >= MAX_MEMBERS:
                    raise ValueError('Too many archive members')
                name = canonical(member.name)
                if name in members:
                    raise ValueError(f'Duplicate archive path: {name}')
                members[name] = member
                raw_type = plain[member.offset + 156:member.offset + 157]
                if member.pax_headers or raw_type != member.type or member.mode & ~0o777:
                    raise ValueError(f'Unsupported extended metadata or mode: {name}')
                record = dict(mode=oct(member.mode), bytes=member.size)
                if member.type in (tarfile.REGTYPE, tarfile.AREGTYPE):
                    total += member.size
                    if member.size < 0 or total > MAX_TAR or name == '.':
                        raise ValueError('Unsupported archive body size or root file')
                    body = archive.extractfile(member).read()
                    if len(body) != member.size:
                        raise ValueError(f'Truncated archive member: {name}')
                    files[name] = body
                    record.update(type='file', sha256=sha256(body))
                elif member.isdir() and member.size == 0:
                    record['type'] = 'directory'
                elif (member.issym() and member.size == 0
                      and ALIASES.get(name) == member.linkname):
                    record.update(type='vendor-library-alias', target=member.linkname)
                else:
                    raise ValueError(f'Unsupported archive member type: {name}')
                records[name] = record
    except (OSError, EOFError, tarfile.TarError) as error:
        raise ValueError(f'Invalid A15W encrypted archive: {error}') from error
    for name, member in members.items():
        parent = posixpath.dirname(name)
        while parent:
            if parent in members and not members[parent].isdir():
                raise ValueError(f'Archive path traverses a non-directory: {name}')
            parent = posixpath.dirname(parent)
        if member.issym():
            target = posixpath.join(posixpath.dirname(name), member.linkname)
            if target not in files:
                raise ValueError(f'Library alias target is not a regular member: {name}')
    for name in REQUIRED:
        if name not in files:
            raise ValueError(f'Missing required regular member: {name}')
    if files['etc/box_product_type'] != b'A15W':
        raise ValueError('Unsupported product: expected embedded A15W')
    version = files['etc/software_version']
    if not re.fullmatch(rb'20\d{2}\.\d{2}\.\d{2}\.\d{4}', version):
        raise ValueError('Unsupported embedded software version format')
    report = dict(
        image_sha256=sha256(image), image_bytes=len(image), product='A15W',
        version=version.decode('ascii'), member_count=len(members), members=records,
        archive_checks='bounded in-memory read; canonical unique paths; explicit member types; no link traversal',
    )
    return report, files
