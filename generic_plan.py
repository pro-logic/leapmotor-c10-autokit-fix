"""Deterministic, non-authorizing proof drafts and ELF insertion arithmetic.

No API in this module applies a plan. A draft is deliberately incomplete even
when its arithmetic is supported. Validation recomputes it from current inputs
and implementation sources, so editing a status or rehashing JSON grants nothing.
"""
from __future__ import annotations

import json
from pathlib import Path

from firmware import sha256
from generic_analysis import Driver

HERE = Path(__file__).resolve().parent
SOURCES = ('generic.py', 'generic_inventory.py', 'generic_analysis.py',
           'generic_packing.py', 'generic_plan.py', 'firmware.py', 'runtime_scripts.py',
           'driver_layout.py', 'driver_patch.py', 'package_overlay.py',
           'verify_packing.py', 'verify_generic.py', 'verify_driver.py',
           'tests/arm_harness.py', 'tests/test_generic.py', 'tests/test_generic_proof.py',
           'templates/once.sh.in', 'templates/finish.sh.in',
           'runtime/c10_start_androidauto_972.sh', 'runtime/c10_capture_init.sh',
           'runtime/c10_usb_capture.sh')
REQUIRED_PROOFS = (
    'exact-packed-to-unpacked-pairing', 'plaintext-open-after-decryption',
    'open-length-and-all-incoming-edges', 'open-register-flags-stack-vfp-liveness',
    'geometry-hu-screen-info', 'geometry-aa-link', 'geometry-type1-response',
    'geometry-remote-cxcy-type240-in-type30', 'touch-aa-channel-and-stack-origin',
    'touch-signed-normalization-and-gesture-packing', 'touch-all-incoming-edges-and-liveness',
    'displaced-instruction-relocation', 'independent-native-emulation',
    'stock-script-control-flow', 'paired-package-and-shell-validation',
)


def align(value, quantum):
    return (value + quantum - 1) // quantum * quantum


def insertion_layout(data, code_bytes=4096, state_bytes=32):
    """Conservative two-LOAD proposal; never writes an ELF or approves a hook."""
    if type(code_bytes) is not int or type(state_bytes) is not int or not (
            4 <= code_bytes <= 65536 and code_bytes % 4 == 0 and 4 <= state_bytes <= 4096
            and state_bytes % 4 == 0):
        raise ValueError('Unsupported code/state reservation')
    d = Driver(data)
    loads = sorted(d.loads, key=lambda p: p['p_vaddr'])
    if len(loads) != 2 or [p['p_flags'] for p in loads] != [5, 6]:
        raise ValueError('Insertion requires exactly RX and RW LOADs')
    rx, rw = loads
    cut = rx['p_offset'] + rx['p_filesz']
    va = rx['p_vaddr'] + rx['p_filesz']
    if (rx['p_offset'] or rx['p_memsz'] != rx['p_filesz'] or cut > rw['p_offset']
            or va % 4 or rx['p_align'] < 4096 or rw['p_align'] < 4096):
        raise ValueError('Unsupported RX extent/order/alignment')
    # A full page of the extended RX must not share the writable mapping.
    if align(va + code_bytes, 4096) > rw['p_vaddr'] // 4096 * 4096:
        raise ValueError('Insufficient RX virtual/page gap')
    state = align(rw['p_vaddr'] + rw['p_memsz'], 4)
    if state + state_bytes > 2**32:
        raise ValueError('State allocation overflows ARM address space')
    segments = [dict(p.header) for p in d.elf.iter_segments()]
    sections = [dict(s.header) for s in d.elf.iter_sections()]
    if d.elf['e_phoff'] + d.elf['e_phentsize'] * d.elf.num_segments() > cut:
        raise ValueError('Program headers cross insertion')
    sh_begin = d.elf['e_shoff']
    sh_end = sh_begin + d.elf['e_shentsize'] * d.elf.num_sections()
    if sh_end > len(data) or sh_begin < cut < sh_end:
        raise ValueError('Invalid/crossing section table')
    quantum = max(p['p_align'] or 1 for p in segments if p['p_offset'] >= cut)
    if quantum & (quantum - 1) or quantum > 1024 * 1024:
        raise ValueError('Unsupported shifted segment alignment')
    gap = align(code_bytes, quantum)
    if len(data) + gap > 2**32 or rx['p_filesz'] + code_bytes > 2**32:
        raise ValueError('File/RX size overflow')
    for p in segments:
        if p['p_offset'] + p['p_filesz'] > len(data):
            raise ValueError('Program segment exceeds source')
        if p['p_type'] != 'PT_LOAD' and p['p_offset'] < cut < p['p_offset'] + p['p_filesz']:
            raise ValueError('Non-LOAD segment crosses insertion')
        if p['p_align'] and (p['p_align'] & (p['p_align'] - 1)
                             or p['p_offset'] % p['p_align'] != p['p_vaddr'] % p['p_align']):
            raise ValueError('Unsupported program segment alignment')
    for s in sections:
        if s['sh_type'] != 'SHT_NOBITS' and (s['sh_offset'] + s['sh_size'] > len(data)
                or s['sh_offset'] < cut < s['sh_offset'] + s['sh_size']):
            raise ValueError('Section exceeds source or crosses insertion')
        if s['sh_flags'] & 2 and s['sh_size']:
            backing = [p for p in loads if p['p_vaddr'] <= s['sh_addr']
                       and s['sh_addr'] + s['sh_size'] <= p['p_vaddr'] + p['p_memsz']]
            if len(backing) != 1:
                raise ValueError('Allocated section lacks unique LOAD backing')
            p = backing[0]
            if s['sh_type'] != 'SHT_NOBITS' and (
                    s['sh_offset'] != p['p_offset'] + s['sh_addr'] - p['p_vaddr']
                    or s['sh_addr'] + s['sh_size'] > p['p_vaddr'] + p['p_filesz']):
                raise ValueError('Allocated section file mapping differs')
    protected = []
    for s in d.elf.iter_sections():
        if s['sh_type'] != 'SHT_NOBITS' and s['sh_size']:
            protected.append(dict(name=s.name, file_offset=s['sh_offset'], bytes=s['sh_size'],
                                  sha256=sha256(s.data())))
    interp = [p for p in d.elf.iter_segments() if p['p_type'] == 'PT_INTERP']
    return dict(status='arithmetic proposal only', insertion_file_offset=cut, rx_va=va,
                code_reservation_bytes=code_bytes, inserted_file_gap_bytes=gap,
                shifted_file_alignment=quantum, state_va=state, state_bytes=state_bytes,
                rw_memsz_extension=state + state_bytes - rw['p_vaddr'] - rw['p_memsz'],
                source_rw_sha256=sha256(data[rw['p_offset']:rw['p_offset'] + rw['p_filesz']]),
                interpreter_sha256=[sha256(p.data()) for p in interp],
                preserved_sections=protected, generation_allowed=False,
                unresolved=['hook-to-code branch reachability after slot assignment',
                            'instruction relocation and liveness',
                            'independent inspection of an actually generated ELF'])


def draft_plan(report, files, driver=None):
    """Inventory plus candidate sites and explicit empty mandatory proof slots."""
    native = report.get('native', {})
    hooks = []
    for role in ('open', 'touch'):
        for candidate in native.get(role + '_candidates', []):
            hooks.append(dict(role=role, candidate_site=candidate['hook'],
                              displaced_instructions=[candidate['hook']['instruction']],
                              incoming_edges=None, live_registers=None, live_flags=None,
                              live_vfp=None, stack_facts=None, evidence_status='local candidate only'))
    proposal = dict(status='unavailable: exact native input required')
    if driver is not None:
        try:
            proposal = insertion_layout(driver)
        except ValueError as error:
            proposal = dict(status='unsupported', reason=str(error))
    capabilities = {key: dict(status='unproved', evidence=[]) for key in REQUIRED_PROOFS}
    return dict(schema='c10-proof-draft-v1', status='incomplete; generation refused',
                patchable=False, generation_allowed=False, hardware_tested=False,
                image_sha256=report['inventory']['image_sha256'],
                packed_driver_sha256=report['packed_driver']['sha256'],
                unpacked_driver_sha256=sha256(driver) if driver is not None else None,
                pairing=report.get('pairing', dict(status='missing')),
                stock_script_sha256={n: sha256(files[n]) for n in (
                    'script/start_main_service.sh', 'script/phone_link_deamon.sh')},
                implementation_sha256={n: sha256((HERE / n).read_bytes()) for n in SOURCES},
                profile=report['c10_profile'], candidate_hooks=hooks,
                required_proofs=capabilities,
                optional_diagnostics=dict(status='unsupported; logger ABI unproved'),
                insertion_proposal=proposal,
                evidence_limits='Candidate and arithmetic evidence only; no proof status can be promoted by editing this draft')


def validate_draft(draft, report, files, driver=None):
    expected = draft_plan(report, files, driver)
    if json.dumps(draft, sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise ValueError('Stale or edited proof draft: recomputed inputs/sources/analysis differ')
    return dict(status='current incomplete draft', generation_allowed=False)
