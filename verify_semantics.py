"""Independent real-input oracles and unmodified discovered-path ARM emulation.

Detector findings supply execution locations; explicit annotations and independent
behavioral expectations below supply the oracle. This does not validate new patch
generation, prove all external entries/contracts, or establish hardware success.
"""
import argparse
import json
from pathlib import Path
import struct
import platform
import sys
import unicorn

from firmware import sha256
from generic_analysis import analyze_driver
from generic_plan import SOURCES, HERE
from tests import generic_arm as arm


def require(condition, message):
    if not condition:
        raise ValueError(message)


ORACLES = {
    'october': dict(sha='0fc23de27693c03455f42b9904df89cff7fc8dccb990f3edfa27c40aea41faee',
        hooks=(0x1df00, 0x1df38, 0x1dd98, 0x1fc78, 0x1ddbe, 0x17b74, 0x17ee4, 0x1fae2),
        selector_setup=0x1e140, selector=0x11f460, initializer=0x64650,
        channels={3: 6, 5: 9, 6: 11, 7: 13, 8: 15, 20: 161},
        consumers=(0x1984c, 0x19868, 0x18598, 0x1b574, 0x1b5c2, 0x17328,
                   0x1b8c0, 9, 0x11f4d0, 0x21d04, 0x21e30)),
    'february': dict(sha='a9fb4ed7aef64a5a7a9cbc221582bcb2716421fc19904a5eafba2e57c6d09eba',
        hooks=(0x1d442, 0x1d47a, 0x1d2e0, 0x1ed70, 0x1d306, 0x18244, 0x184b8, 0x1ebea),
        selector_setup=0x1d678, selector=0x11d094, initializer=0x62df4,
        channels={3: 6, 5: 9, 6: 11, 7: 13, 20: 161},
        consumers=(0x19bd4, 0x19bf0, 0x18e2c, 0x1af48, 0x1af94, 0x17340,
                   0x1b288, 9, 0x11d0e4, 0x20790, 0x2087e)),
}


def annotations(report, oracle):
    require(report['unique_candidates'], 'Need unique October native candidates')
    op, touch = report['open_candidates'][0], report['touch_candidates'][0]
    sem = report['semantic_evidence']
    checked = sem['open'][0]
    require(checked['graph']['closed_within_range'], 'Dispatch graph is not closed within range')
    require(checked['length_check_dominates_hook'] and not checked['failure_path_can_reach_hook'], 'Open length/bypass graph differs')
    require(checked['scratch_registers']['dead'] == ['r0', 'r1', 'r2', 'r3'], 'Open local liveness differs')
    require(len(checked['preprocessing']) == 1, 'Need unique dominant CFB preprocessing evidence')
    crypto = checked['preprocessing'][0]
    require(crypto['cfb_call']['imported']['symbol'] == 'AES_cfb128_encrypt', 'CFB relocation differs')
    actuals = (op['hook']['va'], op['copy_end_va'], checked['graph']['entry'], checked['graph']['end'],
               crypto['call']['va'], crypto['call']['target'], crypto['cfb_call']['va'], touch['hook']['va'])
    for actual, expected in zip(actuals, oracle['hooks']):
        require(actual == expected, f'Independent semantic landmark differs: {actual:#x} != {expected:#x}')
    routing = sem['touch'][0]['routing']
    require(routing['status'] == 'checked bounded routing', 'Touch routing unsupported')
    require((routing['channel_stack_offset'], routing['output_pointer_stack_offset'], routing['selector_setup_va']) == (0x88, 0x90, oracle['selector_setup']), 'Touch stack/selector annotations differ')
    expected = {k: v for k, v in oracle['channels'].items() if k != 20}
    observed = {e['value']: r['channel'] for r in routing['routes'] for e in r['selector_edges']}
    require(observed == expected, 'Independent touch selector/channel mapping differs')
    variables = {e['variable_va'] for r in routing['routes'] for e in r['selector_edges']}
    require(variables == {oracle['selector']}, 'Touch selector variable differs')
    consumers = sem['geometry_consumers']
    require(all(len(v) == 1 for v in consumers.values()), 'Need unique checked geometry consumers')
    roles = {k: v[0] for k, v in consumers.items()}
    locations = (('type1_response', 'function_entry'), ('type1_response', 'copy_start_va'),
                 ('type1_response', 'send_target'), ('remote_cxcy', 'function_entry'),
                 ('remote_cxcy', 'build_va'), ('remote_cxcy', 'send_target'),
                 ('aa_link', 'source_xref_va'), ('aa_link', 'channel'),
                 ('aa_link', 'selector_variable_va'), ('hu_screen_info', 'copy_start_va'),
                 ('hu_screen_info', 'write_call_va'))
    for (role, key), expected in zip(locations, oracle['consumers']):
        require(roles[role][key] == expected, f'Independent {role}/{key} annotation differs')
    require(roles['aa_link']['selector_variable_va'] not in variables,
            'Do not conflate distinct link-state and touch-selector globals')
    return op, touch, sem, roles


def open_checks(data, op):
    count = 0
    for width, height, length in ((2560, 1440, 28), (2560, 1296, 28), (1920, 1080, 28),
                                  (0, 0, 28), (2560, 1440, 0), (2560, 1440, 27), (2560, 1440, 29)):
        fields = (width, height, 30, 0x77, 0x4000, 11, 5)
        m, before = arm.open_copy(data, op, fields, length)
        expected = [bytearray(b) for b in before]
        if length == 28:
            source = list(fields)
            source[3] = 5
            for index, (va, size) in enumerate(m.writable):
                for target, values in ((op['original_open_va'], list(enumerate(source))),
                                       (op['effective_open_va'], [(j, source[j]) for j in (0, 1, 2, 3, 4, 6)])):
                    if va <= target and target + 28 <= va + size:
                        for j, value in values:
                            struct.pack_into('<I', expected[index], target - va + j * 4, value)
        require(m.rw_snapshot() == [bytes(b) for b in expected], 'Original Open modifies unexpected writable bytes')
        require(m.read(m.payload, 28) == struct.pack('<7I', *fields), 'Unmodified Open changed source payload')
        count += 1
    return count


def geometry_checks(data, roles):
    response, remote, link, hu = [roles[k] for k in ('type1_response', 'remote_cxcy', 'aa_link', 'hu_screen_info')]
    counts = dict(type1_response=0, remote_cxcy=0, aa_link=0, hu_screen_info=0)
    for width, height, fps in ((2560, 1440, 30), (2560, 1296, 60), (1920, 972, 24), (1280, 720, 25)):
        payload = struct.pack('<7I', width, height, fps, 5, 0x4000, 11, 5)
        m = arm.Machine(data)
        m.write(response['source_va'], payload)
        before = m.rw_snapshot()
        m.reg(arm.UC_ARM_REG_R0, m.message)
        m.run(response['function_entry'], (response['send_target'],))
        packet = m.packet(m.reg(arm.UC_ARM_REG_R1))
        require(packet == dict(size=28, type=1, payload=payload), 'Type1 response did not use exact effective Open')
        require(m.rw_snapshot() == before, 'Type1 response changed original writable state')
        counts['type1_response'] += 1

        m = arm.Machine(data)
        m.write(remote['source_va'], payload)
        require(remote['open_flag_va'] is not None, 'Remote open-state guard unavailable')
        m.write(remote['open_flag_va'], b'\x01')
        before = m.rw_snapshot()
        m.reg(arm.UC_ARM_REG_R0, m.message)
        mocks = [c['target'] for c in remote['intermediate_calls']]
        m.run(remote['function_entry'], (remote['send_target'], response['send_target']), mocks)
        require(m.reg(arm.UC_ARM_REG_PC) == remote['send_target'] and m.reg(arm.UC_ARM_REG_R0) == 30,
                'Remote broadcast did not select outer type30 send')
        require(m.packet(m.reg(arm.UC_ARM_REG_R1)) == dict(size=28, type=240, payload=payload),
                'Remote broadcast did not use inner240 exact effective Open')
        require(m.rw_snapshot() == before, 'Remote broadcast changed original writable state')
        counts['remote_cxcy'] += 1

        m = arm.Machine(data)
        m.write(link['source_va'], payload)
        m.reg(arm.UC_ARM_REG_R4, 0)
        m.reg(arm.UC_ARM_REG_R5, 0)
        before = m.rw_snapshot()
        m.run(link['source_xref_va'], (link['send_target'],))
        ptr = m.reg(arm.UC_ARM_REG_R2)
        require((m.reg(arm.UC_ARM_REG_R0), m.reg(arm.UC_ARM_REG_R1)) == (5, 9), 'AAP link channel/type differs')
        require(m.read(ptr, 16) == struct.pack('<4I', 2, width, height, fps), 'AAP link dimensions differ')
        require(m.rw_snapshot() == before, 'AAP link slice changed original writable state')
        counts['aa_link'] += 1

        m = arm.Machine(data)
        m.write(hu['source_va'], payload)
        m.reg(arm.UC_ARM_REG_R6, hu['source_va'])
        if hu['output_base_register'] == 'sp':
            output = m.stack + hu['output_base_offset']
        elif hu['output_base_register'] == 'r4' and hu['output_base_offset'] == 0:
            output = m.payload
            m.reg(arm.UC_ARM_REG_R4, output)
        else:
            raise ValueError('HU output location lacks independent emulation fixture')
        m.reg(arm.UC_ARM_REG_R0, 3333)
        m.word(m.stack + 8, 1111)
        m.word(m.stack + 12, 2222)
        before = m.rw_snapshot()
        m.run(hu['copy_start_va'], (hu['copy_end_va'],))
        require(m.read(output, 24) == struct.pack('<6I', width, height, 1111, 2222, fps, 3333),
                'HU record geometry or nongeometry fields differ')
        m.run(hu['write_setup_va'], (hu['write_target'],))
        require(m.read(m.reg(arm.UC_ARM_REG_R0), 15) == b'HU_SCREEN_INFO\0'
                and m.reg(arm.UC_ARM_REG_R1) == output and m.reg(arm.UC_ARM_REG_R2) == 24,
                'HU named write arguments differ')
        require(m.rw_snapshot() == before, 'HU slice changed original writable state')
        counts['hu_screen_info'] += 1

    # Actual remote function must bypass its inner240 broadcast on zero geometry
    # or closed Open state. Only its diagnostic logger is mocked.
    for width, height, opened in ((0, 1296, 1), (2560, 0, 1), (2560, 1296, 0)):
        m = arm.Machine(data)
        m.write(remote['source_va'], struct.pack('<7I', width, height, 30, 5, 0, 11, 5))
        m.write(remote['open_flag_va'], bytes([opened]))
        m.reg(arm.UC_ARM_REG_R0, m.message)
        # Failure-path logger has a distinct call site but the same target.
        m.run(remote['function_entry'], (remote['send_target'], response['send_target']),
              [c['target'] for c in remote['intermediate_calls']])
        require(m.reg(arm.UC_ARM_REG_PC) == response['send_target'], 'Invalid geometry reached RemoteCxCy broadcast')
        require(m.packet(m.reg(arm.UC_ARM_REG_R1))['type'] == 1, 'Remote fallback message type differs')
    counts['remote_guard_cases'] = 3
    return counts


def verify(path, fixture='october'):
    data = Path(path).read_bytes()
    oracle = ORACLES[fixture]
    require(sha256(data) == oracle['sha'], 'Independent verifier requires exact selected fixture')
    native = analyze_driver(data)
    op, touch, sem, roles = annotations(native, oracle)
    opens = open_checks(data, op)
    geometry = geometry_checks(data, roles)
    initializer = roles['type1_response']['initializer_target']
    require(initializer == oracle['initializer'], 'Independent packet initializer annotation differs')
    cases = 0
    for selector, channel in oracle['channels'].items():
        for raw_action in (14, 15, 16):
            for pointer in (0, 7, 255):
                for y in (-2147483648, -1, 0, 500, 5000, 10000, 10001, 2147483647):
                    x = -2147483648 if pointer == 255 else 2147483647 if pointer == 7 else 9123
                    m, packet = arm.touch_dispatch(data, touch, sem['touch'][0], selector, raw_action,
                                                   pointer, x, y, initializer)
                    require(packet['type'] == channel and packet['size'] == 32, 'Touch routed to wrong native channel')
                    require(struct.unpack_from('<2I', packet['payload']) == (24, 11), 'Touch inner header differs')
                    expected_action = 1 if raw_action == 14 or raw_action == 15 and selector == 3 else 2 if raw_action == 15 else 0
                    require(struct.unpack_from('<I', packet['payload'], 24)[0] == expected_action | pointer << 8,
                            'Touch action/pointer translation differs')
                    require(struct.unpack_from('<2d', packet['payload'], 8) == (x / 10000.0, y / 10000.0),
                            'Signed touch normalization differs')
                    require(m.read(m.payload + 4, 8) == struct.pack('<ii', x, y), 'Touch altered input coordinates')
                    require(m.rw_snapshot() == m.initial_rw, 'Touch slice changed original writable state')
                    cases += 1
    return dict(status='PASS', fixture=fixture, driver_sha256=sha256(data), semantic_evidence=sem,
                python=sys.version, platform=platform.platform(), unicorn_version=unicorn.__version__,
                source_sha256={n: sha256((HERE / n).read_bytes()) for n in SOURCES},
                original_open_cases=opens, geometry_cases=geometry, native_touch_dispatch_cases=cases,
                evidence_level='static bounded CFG/data flow plus unmodified-path Unicorn emulation',
                mocks=['host allocation via imported malloc/free/realloc', 'RemoteCxCy diagnostic logger return'],
                limits=['Calls stop before actual IPC/HU file writes; HU copy and write setup are separate slices',
                        'AAP link emulation begins after the strcmp gate; its gate is checked statically',
                        'No new patch code generated or emulated; flags/VFP/stack hook preservation remains unproved',
                        'Full decryption helper conditions/key derivation and outside entries remain unproved',
                        'No new installer/shell/hardware validation'],
                complete_functional_proof=False, generation_allowed=False, hardware_tested=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--october-driver', type=Path, help='Legacy name for exact October fixture')
    parser.add_argument('--driver', type=Path)
    parser.add_argument('--fixture', choices=tuple(ORACLES), default='october')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if bool(args.october_driver) == bool(args.driver) or args.october_driver and args.fixture != 'october':
        parser.error('Supply exactly --driver or legacy --october-driver with matching fixture')
    report = verify(args.driver or args.october_driver, args.fixture)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({k: v for k, v in report.items() if k not in ('semantic_evidence', 'source_sha256')}, indent=2))
