"""Real-input channel/storage and actual-span ABI/entry research, in memory only.

The selected fixture pins are independent test oracles, never discovery inputs.
Static reference candidates are retained and cannot authorize native generation.
"""
import argparse
import json
from pathlib import Path

from unicorn import arm_const as regs

from firmware import sha256
from generic_analysis import Driver, analyze_driver
from generic_abi import (hook_transfer_contract, observer_frame_contract,
                         validate_stack_separation, verify_unwind_tail_extension)
from generic_global_flow import static_entry_inventory
from generic_plan import HERE, SOURCES
from tests.generic_arm import Machine
from tests.native_experiment import experiment
from verify_native_experiment import elf_check
from verify_semantics import ORACLES, require

STORAGE_ORACLES = {
    'october': dict(storage=0x64670, resize=0x646fa),
    'february': dict(storage=0x62e14, resize=0x62e9e),
}


def storage_checks(data, storage, initializer):
    """Execute actual storage paths with explicit allocator/OS return contracts."""
    count = 0
    for prior in ('empty', 'heap', 'mapping'):
        for length in (0, 1, 16, 28, 32, 96, 256, 1024):
            for fail in (False, True):
                m = Machine(data)
                m.reg(regs.UC_ARM_REG_R0, m.message)
                m.run(initializer, (m.stop,))
                owner, capacity = 0, 0
                if prior != 'empty':
                    capacity = 256
                    owner = m.allocate(capacity)
                    m.word(m.message + 4, 16)
                    m.word(m.message + 16, owner + 96)
                    m.word(m.message + 20, owner)
                    m.word(m.message + 24, capacity)
                    m.word(m.message + 28, 96)
                    if prior == 'mapping':
                        m.word(m.message + 32, 7)
                before_rw = m.rw_snapshot()
                stack = m.read(m.stack - 64, 128)
                imported = []
                def malloc(machine):
                    size = machine.reg(regs.UC_ARM_REG_R0)
                    require(size == length + 192, 'Storage malloc request differs')
                    imported.append(('malloc', size))
                    return {regs.UC_ARM_REG_R0: 0 if fail else machine.allocate(size)}
                def munmap(machine):
                    require((machine.reg(regs.UC_ARM_REG_R0), machine.reg(regs.UC_ARM_REG_R1)) ==
                            (owner, capacity), 'Storage munmap arguments differ')
                    imported.append(('munmap', owner))
                    machine.allocations.pop(owner)
                    return {regs.UC_ARM_REG_R0: 0}
                def close(machine):
                    require(machine.reg(regs.UC_ARM_REG_R0) == 7, 'Storage close fd differs')
                    imported.append(('close', 7))
                    return {regs.UC_ARM_REG_R0: 0}
                m.reg(regs.UC_ARM_REG_R0, m.message)
                m.reg(regs.UC_ARM_REG_R1, 17)
                m.reg(regs.UC_ARM_REG_R2, length)
                m.reg(regs.UC_ARM_REG_LR, m.stop | 1)
                saved = {r: m.reg(r) for r in (regs.UC_ARM_REG_R4, regs.UC_ARM_REG_R5,
                         regs.UC_ARM_REG_R6, regs.UC_ARM_REG_R7, regs.UC_ARM_REG_SP)}
                m.run(storage, (m.stop,), import_handlers={'malloc': malloc, 'munmap': munmap, 'close': close})
                allocated = length != 0 and (prior != 'heap' or length + 192 > capacity)
                failed = allocated and fail
                require(m.reg(regs.UC_ARM_REG_R0) == int(not failed), 'Storage return value differs')
                require(all(m.reg(r) == value for r, value in saved.items()), 'Storage callee-saved/SP drift')
                require(m.word(m.message + 8) == 17, 'Storage type assignment differs')
                require(m.word(m.message + 32) == 0xffffffff, 'Storage mapping descriptor was not reset')
                if prior == 'mapping':
                    require([name for name, _ in imported[:2]] == ['munmap', 'close'], 'Mapping cleanup order differs')
                if length and not failed:
                    result_owner = m.word(m.message + 20)
                    require(result_owner in m.allocations, 'Storage payload has no recognized owner')
                    require(m.word(m.message + 16) == result_owner + 96 and m.word(m.message + 4) == length,
                            'Storage payload bias/length differs')
                    require(m.word(m.message + 24) >= length + 192, 'Storage capacity is insufficient')
                    validate_stack_separation(m.stack, 56, [('descriptor', m.message, 36),
                        ('payload', m.word(m.message + 16), length)])
                else:
                    require(all(m.word(m.message + offset) == 0 for offset in (4, 16, 20, 24)),
                            'Empty/failed storage retains an owner or payload')
                require(m.rw_snapshot() == before_rw, 'Storage changed unrelated writable globals')
                after = bytearray(m.read(m.stack - 64, 128))
                after[40:64] = stack[40:64]
                require(after == stack, 'Storage writes outside its 24-byte saved frame')
                count += 1
    return count


def verify(path, fixture):
    data = Path(path).read_bytes()
    require(sha256(data) == ORACLES[fixture]['sha'], 'Independent contracts verifier requires exact selected fixture')
    native = analyze_driver(data)
    channel = native['channel_storage_evidence']
    require(channel['status'] == 'checked bounded channel and conditional storage relationships',
            'Native channel/storage relationships are unsupported')
    oracle = STORAGE_ORACLES[fixture]
    require(channel['packet_storage']['function_entry'] == oracle['storage'] and
            channel['response_resize']['function_entry'] == channel['touch_resize']['function_entry'] == oracle['resize'],
            'Independent storage/wrapper landmarks differ')
    require(channel['channel']['channel'] == 9 and channel['channel']['selector_value'] == 5 and
            channel['channel']['touch_selector_va'] != channel['channel']['distinct_link_state_va'],
            'Independent AAP/touch channel relationship differs')
    initializer = native['semantic_evidence']['geometry_consumers']['type1_response'][0]['initializer_target']
    cases = storage_checks(data, oracle['storage'], initializer)
    print(f'{fixture}: {cases} actual packet-storage path cases PASS', flush=True)
    changed, manifest = experiment(data, native, plaintext_safe=True)
    original, output = Driver(data), Driver(changed)
    elf = elf_check(data, changed, manifest)
    hooks = [hook_transfer_contract(original, output, hook, hook['target_va'], hook['transfer'] == 'call')
             for hook in manifest['hooks']]
    unwind = verify_unwind_tail_extension(original, output, manifest['cfb_observer_unwind'])
    observer_end = manifest['cfb_observer_unwind']['appended_entries'][-1]['function_va']
    frame = observer_frame_contract(output, manifest['cfb_observer_va'], observer_end)
    require(frame['synchronous_unwind_registered'], 'Observer synchronous unwind is unregistered')
    spans = [(f'hook-{i}-interior', hook['va'] + 2, 2) for i, hook in enumerate(manifest['hooks'])]
    spans.append(('actual-rx-extension', manifest['layout']['rx_va'], manifest['code_bytes']))
    entries = static_entry_inventory(original, spans)
    # Retain unresolved candidates instead of losing the audit when its refusal
    # gate fires. This differs from passing the bounded checks above.
    return dict(schema='c10-native-contract-experiment-v1', status='INCOMPLETE', component_checks='PASS', fixture=fixture,
                driver_sha256=sha256(data), experimental_sha256=sha256(changed),
                channel_storage_evidence=channel, storage_path_cases=cases,
                independent_elf=elf, hook_transfers=hooks, unwind=unwind, observer_frame=frame,
                static_entry_inventory=entries,
                entry_gate=dict(status='refused', complete_indirect_target_proof=False,
                    direct_candidates=len(entries['direct']['hits']),
                    absolute_candidates=len(entries['absolute']['hits']),
                    constructor_candidates=len(entries['constructors']['hits']),
                    partial_movt_candidates=len(entries['constructors']['partial_movt_constructors']),
                    reason='Enumerated candidates and all indirect-entry/caller ownership contracts remain unresolved'),
                source_sha256={name: sha256((HERE / name).read_bytes()) for name in SOURCES},
                evidence_level='bounded static evidence, actual-ELF checks and actual native storage emulation',
                mocks=['malloc/free allocation ownership', 'munmap/close success; no OS mapping is performed'],
                limits=['PASS covers the enumerated checks, not completion of all generation gates',
                        'Absolute/constructor candidates remain visible; arbitrary indirect targets are unproved',
                        'All-caller payload ownership, stack limits and asynchronous unwind remain unproved'],
                generation_allowed=False, installable_images_emitted=False, hardware_tested=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--driver', required=True, type=Path)
    parser.add_argument('--fixture', required=True, choices=tuple(ORACLES))
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Refusing to overwrite evidence')
    result = verify(args.driver, args.fixture)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(status=result['status'], fixture=args.fixture, storage_path_cases=result['storage_path_cases'],
                         component_checks=result['component_checks'], entry_gate=result['entry_gate']), indent=2))
    parser.exit(2, 'Bounded checks passed; entry/ownership generation gate remains refused (evidence saved).\n')
