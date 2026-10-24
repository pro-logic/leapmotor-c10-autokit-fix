"""A15W encrypted update overlays; adapted from lvalen91/CPC200-CCPA_resources.

Archives are read in memory. Vendor files are supplied locally, never bundled.
"""
from __future__ import annotations
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY = b"AutoPlay9uPT4n17".ljust(16, b"\0")
HERE = Path(__file__).resolve().parent
ONCE = (HERE / "templates/once.sh.in").read_text(encoding="utf-8")
FINISH = (HERE / "templates/finish.sh.in").read_text(encoding="utf-8")

def md5(data):
    return hashlib.md5(data).hexdigest()

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def crypt(data: bytes, decrypt: bool) -> bytes:
    aligned = len(data) // 16 * 16
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(KEY))
    worker = cipher.decryptor() if decrypt else cipher.encryptor()
    return worker.update(data[:aligned]) + worker.finalize() + data[aligned:]

def read_archive(image: bytes) -> tuple[bytes, list[tarfile.TarInfo], dict[str, bytes]]:
    plain = crypt(image, decrypt=True)
    with tarfile.open(fileobj=io.BytesIO(plain), mode="r:gz") as archive:
        members = archive.getmembers()
        bodies = {
            member.name: archive.extractfile(member).read()
            for member in members
            if member.isfile()
        }
    return plain, members, bodies

def add_regular(archive: tarfile.TarFile, name: str, body: bytes, mode: int, mtime: int) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(body)
    info.mode = mode
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    info.mtime = mtime
    archive.addfile(info, io.BytesIO(body))

def write_package(payload: dict, checks: str, rollback: bool, *, output_directory: Path | None = None,
            action_label: str | None = None, used_name: str | None = None,
            enforcement_description: str | None = None, finish_steps: str = "",
            finish_template: str | None = None) -> dict:
    action = action_label or ("logging-only rollback" if rollback else "fixed 1920x972 AA launch")
    used = used_name or ("A15W_C10_972_Rollback.used" if rollback else "A15W_C10_Fixed_972.used")
    once = ONCE.replace("@ACTION@", action).replace("@BASELINE_CHECKS@", checks).encode()
    copy_checks = []
    for name, body in payload.items():
        path = name[1:]
        copy_checks.append(f'''[ "$(md5sum {path} | awk '{{print $1}}')" = {md5(body)} ] || fail 'Copy verification failed: {path}' ''')
    cleanup = "rm -f /script/c10_start_androidauto_972.sh || fail 'Cannot remove launch hook'" if rollback else ":"
    if finish_steps:
        cleanup += "\n" + finish_steps
    finish = (finish_template if finish_template is not None else FINISH).replace("@COPY_CHECKS@", "\n".join(copy_checks)).replace(
        "@EXECUTABLES@", " ".join(name[1:] for name in payload if name.endswith(".sh"))
    ).replace("@CLEANUP@", cleanup).replace("@ACTION@", action).replace("@USED@", used).encode()
    files = {**payload, "./tmp/once.sh": once, "./tmp/finish.sh": finish}
    stream = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for directory in (".", "./script", "./tmp"):
                entry = tarfile.TarInfo(directory)
                entry.type = tarfile.DIRTYPE
                entry.mode = 0o755
                archive.addfile(entry)
            for name, body in files.items():
                add_regular(archive, name, body, 0o755, 0)
    image = crypt(stream.getvalue(), decrypt=False)
    _, members, actual = read_archive(image)
    if actual != files or len(members) != len(files) + 3:
        raise RuntimeError("Archive round trip or payload scope verification failed")
    directory = Path(output_directory)
    directory.mkdir(parents=True, exist_ok=True)
    output = directory / "A15W_Update.img"
    output.write_bytes(image)
    manifest = {
        "output": (Path(directory.name) / output.name).as_posix(),
        "output_bytes": len(image), "output_sha256": sha256(image),
        "requires_model": "A15W", "requires_version": "2025.10.15.1127",
        "mode": action,
        "aa_content_size": None if rollback else {"width": 1920, "height": 972},
        "enforcement": enforcement_description or ("Host controlled" if rollback else "Immediately before each AA process launch; no background resolution guard"),
        "usb_snapshot_mode": "Flush data, publish directory, flush publication; retain three completed snapshots",
        "open_handling_modified": False, "projection_binaries_modified": False,
        "input_channel_modified": False, "dpi_modified": False,
        "hardware_tested": False,
        "members": {name: sha256(body) for name, body in files.items()},
    }
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest
