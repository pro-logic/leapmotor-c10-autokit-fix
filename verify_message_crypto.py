"""Independent two-layout Open message-CFB contract and bypass emulation.

Actual marker, guard, key/IV derivation and dispatch instructions execute.
memset, diagnostic logging and OpenSSL primitives have explicit host contracts;
this neither executes the vendor libraries nor proves runtime caller provenance.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import platform
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import cryptography
import unicorn
from unicorn.arm_const import UC_ARM_REG_R8, UC_ARM_REG_R11

from firmware import sha256
from generic_analysis import analyze_driver
from generic_plan import HERE, SOURCES
from tests import generic_arm as arm


# Independent fixture annotations, never imported by semantic discovery.
ORACLES = {
    'october': dict(sha='0fc23de27693c03455f42b9904df89cff7fc8dccb990f3edfa27c40aea41faee',
        helper=0x17b74, marker_helper=0x64620, active=0x11f408, table=0x6d0d4,
        logger=0x688d4, call=0x1ddbe, hook=0x1df00),
    'february': dict(sha='a9fb4ed7aef64a5a7a9cbc221582bcb2716421fc19904a5eafba2e57c6d09eba',
        helper=0x18244, marker_helper=0x62dc4, active=0x11d03c, table=0x6b5d1,
        logger=0x66e64, call=0x1d306, hook=0x1d442),
}
MARKER = 0x55bb55bb
SAVED = (arm.UC_ARM_REG_R4, arm.UC_ARM_REG_R5, arm.UC_ARM_REG_R6, arm.UC_ARM_REG_R7,
         UC_ARM_REG_R8, arm.UC_ARM_REG_R9, arm.UC_ARM_REG_R10, UC_ARM_REG_R11)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def expected_material(driver, table, seed):
    """Independent arithmetic oracle: C remainder truncates toward zero."""
    key = bytearray()
    for index in range(16):
        value = (seed + index) & 0xffffffff
        signed = value - 2**32 if value >= 2**31 else value
        remainder = signed % 16 if signed >= 0 else -((-signed) % 16)
        key.extend(driver.read(table + remainder, 1))
    iv = bytearray(16)
    for index, offset in enumerate((1, 4, 9, 12)):
        iv[offset] = (seed >> (index * 8)) & 255
    return bytes(key), bytes(iv)


def case(data, oracle, seed, active, marker, length, dispatch=False):
    m = arm.Machine(data)
    key, iv = expected_material(m.driver, oracle['table'], seed)
    plain = struct.pack('<7I', 2560, 1440, 30, 5, 0x4000, 11, 5) + bytes(range(36))
    enc = Cipher(algorithms.AES(key), modes.CFB(iv)).encryptor()
    cipher = enc.update(plain) + enc.finalize()
    supplied = cipher if marker == MARKER else plain
    expected = plain[:length] + supplied[length:] if marker == MARKER and active > 0 and length else supplied
    descriptor = struct.pack('<8I', marker, length, 1, 0x11223344, m.payload, 0x22334455, 0x33445566, 0x44556677)
    m.write(m.message, descriptor)
    m.write(m.payload - 16, b'\xa5' * 16 + supplied + b'\x5a' * 16)
    m.word(oracle['active'], active)
    saved_values = {reg: 0x12340000 + index * 0x101 for index, reg in enumerate(SAVED)}
    for reg, value in saved_values.items():
        m.reg(reg, value)
    if dispatch:
        require((seed & 0xffffffff) == (active & 0xffffffff), 'Dispatch reads seed from actual crypto-state word')
        m.reg(arm.UC_ARM_REG_R4, oracle['active'])
        m.reg(arm.UC_ARM_REG_R6, m.message)
        saved_values[arm.UC_ARM_REG_R4] = oracle['active']
        saved_values[arm.UC_ARM_REG_R6] = m.message
    else:
        m.reg(arm.UC_ARM_REG_R0, 0)
        m.reg(arm.UC_ARM_REG_R1, m.message)
        m.reg(arm.UC_ARM_REG_R2, seed & 0xffffffff)
    initial_rw = m.rw_snapshot()
    counts = Counter()
    schedule = None
    helper_sp = m.stack - 28 - 0x12c

    def memset(machine):
        target, value, size = [machine.reg(r) for r in (arm.UC_ARM_REG_R0, arm.UC_ARM_REG_R1, arm.UC_ARM_REG_R2)]
        require(target in (helper_sp + 0x14, helper_sp + 0x24) and value == 0 and size == 16,
                'Native memset arguments differ')
        machine.write(target, bytes(16))
        counts['memset'] += 1

    def set_key(machine):
        nonlocal schedule
        pointer, bits, schedule = [machine.reg(r) for r in (arm.UC_ARM_REG_R0, arm.UC_ARM_REG_R1, arm.UC_ARM_REG_R2)]
        require(pointer == helper_sp + 0x24 and bits == 128 and schedule == helper_sp + 0x34,
                'Native AES key setup arguments differ')
        require(machine.read(pointer, 16) == key, 'Native signed key-table derivation differs')
        # A synthetic schedule marks ownership; the host CFB primitive below
        # consumes the checked raw key. No vendor OpenSSL machine code runs.
        machine.write(schedule, b'\x96' * 244)
        machine.reg(arm.UC_ARM_REG_R0, 0)
        counts['set_key'] += 1

    def cfb(machine):
        source, output, size, actual_schedule = [machine.reg(r) for r in
            (arm.UC_ARM_REG_R0, arm.UC_ARM_REG_R1, arm.UC_ARM_REG_R2, arm.UC_ARM_REG_R3)]
        sp = machine.reg(arm.UC_ARM_REG_SP)
        iv_pointer, num_pointer, direction = struct.unpack('<3I', machine.read(sp, 12))
        require((source, output, size, actual_schedule, iv_pointer, num_pointer, direction) ==
                (m.payload, m.payload, length, schedule, helper_sp + 0x14, helper_sp + 0x10, 0),
                'Native CFB register/stack arguments differ')
        require(counts['set_key'] == 1 and machine.word(num_pointer) == 0, 'Native CFB key/num initialization differs')
        require(machine.read(iv_pointer, 16) == iv, 'Native CFB seed-derived IV differs')
        dec = Cipher(algorithms.AES(key), modes.CFB(iv)).decryptor()
        result = dec.update(machine.read(source, size)) + dec.finalize()
        machine.write(output, result)
        machine.word(num_pointer, size % 16)
        machine.reg(arm.UC_ARM_REG_R0, 0)
        counts['cfb'] += 1

    if dispatch:
        # Run the actual three argument-setup instructions, helper, return and
        # native type/length dispatch. Stop at the hook or malformed Open target.
        start = oracle['call'] - 6
        stops = (oracle['hook'],)
    else:
        start, stops = oracle['helper'], (m.stop,)
    m.run(start, stops, (oracle['logger'],), limit=5000,
          import_handlers={'memset': memset, 'AES_set_encrypt_key': set_key, 'AES_cfb128_encrypt': cfb})
    decrypt = marker == MARKER and active > 0 and length != 0
    log = marker == MARKER and active <= 0
    require(counts == (Counter(memset=2, set_key=1, cfb=1) if decrypt else Counter()),
            'Native decrypt/bypass import trace differs')
    require(sum(e.get('mock') == 'explicit I/O return' for e in m.events) == int(log),
            'Native inactive-crypto diagnostic trace differs')
    require(m.read(m.payload - 16, 96) == b'\xa5' * 16 + expected + b'\x5a' * 16,
            'Native preprocessing changed unexpected payload bytes or failed decryption')
    require(m.read(m.message, 32) == descriptor, 'Native preprocessing mutated descriptor')
    require(m.rw_snapshot() == initial_rw, 'Native preprocessing mutated original writable mapping')
    require(m.reg(arm.UC_ARM_REG_SP) == m.stack, 'Native preprocessing failed stack balance')
    require(all(m.reg(r) == v for r, v in saved_values.items()), 'Native preprocessing clobbered callee-saved register')
    return dict(decrypt=decrypt, diagnostic_bypass=log, encrypted_inactive_reached_hook=dispatch and log,
                helper_instructions=len(m.visited))


def verify(path, fixture):
    data = Path(path).read_bytes()
    oracle = ORACLES[fixture]
    require(sha256(data) == oracle['sha'], 'Independent message-CFB verifier requires exact selected fixture')
    native = analyze_driver(data)
    preprocessing = native['semantic_evidence']['open'][0]['preprocessing']
    require(len(preprocessing) == 1, 'Need unique preprocessing finding')
    contract = preprocessing[0]['open_cfb_contract']
    require(contract['status'] == 'checked entry-relative Open CFB contract', 'Unsupported message-CFB contract')
    expected = (oracle['helper'], oracle['marker_helper'], oracle['active'], oracle['table'], oracle['logger'], MARKER)
    actual = (contract['helper_entry'], contract['encrypted_flag']['function_entry'], contract['active_state_va'],
              contract['key_derivation']['table_va'], contract['logger_target'], contract['encrypted_flag']['encrypted_marker'])
    require(actual == expected, 'Independent message-CFB landmarks differ')
    require(contract['caller_seed_source'].get('source_va') == oracle['active'], 'Caller seed/state alias differs')
    require(not contract['plaintext_at_hook_proved'], 'Inactive encrypted path must withhold plaintext proof')
    totals = Counter()
    for seed in (0, 1, 15, 16, 0x01020304, 0x7ffffff0, 0x7fffffff, 0x80000000, 0x80000001, 0xfffffff1, 0xffffffff):
        for active in (-2147483648, -1, 0, 1, 2147483647):
            for marker in (MARKER, 0x55aa55aa, MARKER ^ 1):
                for length in (0, 1, 15, 16, 17, 28, 29):
                    result = case(data, oracle, seed, active, marker, length)
                    totals['helper_cases'] += 1
                    totals['decrypt_cases'] += int(result['decrypt'])
                    totals['diagnostic_bypasses'] += int(result['diagnostic_bypass'])
    for state in (-2147483648, -1, 0, 1, 0x01020304, 2147483647):
        for marker in (MARKER, 0x55aa55aa, MARKER ^ 1):
            result = case(data, oracle, state & 0xffffffff, state, marker, 28, dispatch=True)
            totals['open_dispatch_cases'] += 1
            totals['encrypted_inactive_hook_counterexamples'] += int(result['encrypted_inactive_reached_hook'])
    return dict(status='PASS', fixture=fixture, driver_sha256=sha256(data), counts=dict(totals),
                contract=contract, evidence_level='static restricted contract plus actual native helper/dispatch emulation',
                python=sys.version, platform=platform.platform(), unicorn_version=unicorn.__version__,
                cryptography_version=cryptography.__version__,
                source_sha256={n: sha256((HERE / n).read_bytes()) for n in SOURCES},
                mocks=['memset host implementation', 'diagnostic logger return',
                       'AES key schedule/CFB via host cryptography; vendor libraries not executed'],
                limits=['Full caller and outside-entry contracts remain unproved',
                        'Runtime state initialization/writers/concurrency remain unproved',
                        'Helper seeds vary independently in direct cases; actual dispatch reads seed from active-state word',
                        'No universal plaintext postcondition, generated ELF, installer or hardware test'],
                plaintext_at_hook_proved=False, generation_allowed=False, hardware_tested=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--driver', required=True, type=Path)
    parser.add_argument('--fixture', required=True, choices=tuple(ORACLES))
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Refusing to overwrite existing evidence')
    report = verify(args.driver, args.fixture)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({k: report[k] for k in ('status', 'fixture', 'counts', 'plaintext_at_hook_proved', 'generation_allowed')}, indent=2))
