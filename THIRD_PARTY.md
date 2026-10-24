# Credits and third-party material

## Firmware research and build tooling

Based on [lvalen91/CPC200-CCPA_resources](https://github.com/lvalen91/CPC200-CCPA_resources),
MIT, copyright 2025 lvalen91. The development checkout started from commit
`b82b38249cc551390512d96f85c372107d678c1d` and contained subsequent local C10
work. The v13 changes are not claimed to be present at that upstream commit.
Its copyright and licence are retained in this repository's LICENSE.

The native patch and validators, A15W archive format code, installer templates,
AA session guard and USB collector were adapted from that local C10 work into
standalone tools. New standalone modifications: copyright 2026 pro-logic.

## User-supplied vendor firmware

The original firmware and driver are vendor material. In particular, the startup
script carries a DongGuan HeWei Communication Technologies Co. Ltd. notice.
The builder derives replacement vendor scripts from your supplied image and
preserves their original notices. It produces a modified vendor executable and
includes the original executable in the paired rollback. No complete vendor
startup script or driver is committed here.

The MIT licence for this project's code does not relicense the vendor components.
Obtain the inputs separately; establish applicable redistribution rights before
publishing generated images. Ignoring inputs/dist in Git keeps them out of
ordinary source commits, but is not a legal determination about those files.

## Optional hardware unpacking tool

The original driver exporter uses the hardware-AES-aware UPX tool from
[ludwig-v/wireless-carplay-dongle-reverse-engineering](https://github.com/ludwig-v/wireless-carplay-dongle-reverse-engineering),
commit `b437135316275a5d3c375bdd1ceac2a6bcf1315b`, `Debug_Tools/upx`.
Corresponding source changes are in `Debug_Tools/Source/upx-3.96/patchUPX.diff`;
consult the upstream licence and source before obtaining or redistributing it.
The binary and its source are not included in this repository.

Expected SHA-256:
`c41472232b5eb4b3ca5ffa0ea7a677be7fd832a8a10446bd4ba4077964ad4f42`.

## Python dependencies

Cryptography, Keystone Engine, Capstone, pyelftools and Unicorn are installed
separately using requirements.txt; none are vendored in this repository. Their
own licences apply. The build performs assembly, disassembly and emulation on
the host rather than executing the vendor ARM program on the host OS.
