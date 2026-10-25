"""Source-generated relocated message-CFB paths and structural adversaries."""
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from driver_layout import assemble
from generic_analysis import Driver
from generic_crypto import caller_seed_source, open_cfb_contract
from generic_flow import ThumbGraph
from tests.test_generic import native_fixture


def crypto_fixture(base=0x430000, change=None, import_change=None):
    data = bytearray(native_fixture(base))
    source = f'''
push.w {{r4,r5,r6,r7,r8,sb,lr}}
mov r8,r0
sub sp,#0x12c
mov r0,r1
mov r4,r1
mov r7,r2
bl {base + 0x800}
ldr r3, active_ptr
cmp r0,#0
beq gate
cmp.w r8,#0
bne gate
ldr r2,[r3]
cmp r2,#0
bgt gate
ldr r3,[r4,#8]
cmp r3,#1
beq log_open
b exit
log_open:
ldr r3, log_ptr
b log
log:
ldr r1, log_ptr
movs r0,#6
ldr r2, log_ptr
bl {base + 0x820}
b exit
gate:
ldr r3,[r3]
cmp r3,#0
ble exit
ldr r3,[r4,#4]
cmp r3,#0
beq exit
cmp.w r8,#0
beq flag_check
b exit
flag_check:
mov r0,r4
bl {base + 0x800}
cmp r0,#0
beq exit
add r5,sp,#0x14
add.w sb,sp,#0x24
movs r1,#0
movs r2,#0x10
mov r0,r5
add r6,sp,#0x10
blx {base + 0x900}
movs r1,#0
mov r0,sb
movs r2,#0x10
blx {base + 0x900}
ldr r0, table_ptr
asrs r3,r7,#8
movs r1,#0
strb r3,[r5,#4]
asrs r3,r7,#0x10
str r1,[r6]
strb r3,[r5,#9]
lsrs r3,r7,#0x18
strb r7,[r5,#1]
strb r3,[r5,#0xc]
key_loop:
ldr r3, mask
adds r2,r1,r7
ands r3,r2
cmp r3,#0
ittt lt
addlt.w r3,r3,#-1
ornlt r3,r3,#0xf
addlt r3,#1
ldrb r3,[r3,r0]
strb.w r3,[sb,r1]
adds r1,#1
cmp r1,#0x10
bne key_loop
mov r0,sb
movs r1,#0x80
add r2,sp,#0x34
blx {base + 0x904}
cmp.w r8,#0
beq decrypt
b exit
decrypt:
stm.w sp,{{r5,r6,r8}}
add r3,sp,#0x34
ldr r0,[r4,#0x10]
ldr r2,[r4,#4]
mov r1,r0
blx {base + 0x908}
exit:
add sp,#0x12c
pop.w {{r4,r5,r6,r7,r8,sb,pc}}
.align 2
active_ptr: .word {base + 0x3020}
table_ptr: .word {base + 0x960}
log_ptr: .word {base + 0x980}
mask: .word 0x8000000f
'''
    leaf = '''ldr r0,[r0]
ldr r3,marker
subs r3,r0,r3
rsbs r0,r3,#0
adcs r0,r3
bx lr
.align 2
marker: .word 0x12345678
'''
    if change:
        old, new = change
        if old in source:
            source = source.replace(old, new, 1)
        else:
            assert old in leaf
            leaf = leaf.replace(old, new, 1)
    for offset, code in ((0x100, assemble(source, base + 0x100)), (0x800, assemble(leaf, base + 0x800))):
        data[offset:offset + len(code)] = code
    symbols = {base + 0x900: 'memset', base + 0x904: 'AES_set_encrypt_key', base + 0x908: 'AES_cfb128_encrypt'}
    if import_change:
        symbols[base + 0x908] = import_change
    d = Driver(bytes(data))
    # Only the synthetic fixture's fake import veneer resolver is mocked.
    with patch('generic_flow.plt_import', side_effect=lambda driver, target:
               dict(symbol=symbols[target], plt_va=target, got_va=base + 0x3040) if target in symbols else None):
        graph = ThumbGraph(d, base + 0x100, base + 0x700)
    return open_cfb_contract(SimpleNamespace(driver=d), graph, dict(target=base + 0x100))


class MessageCryptoTests(unittest.TestCase):
    def test_caller_seed_pointer_is_derived_and_clobbers_refused(self):
        for base in (0x10000, 0x430000):
            for clobber in (False, True):
                data = bytearray(native_fixture(base))
                code = assemble(f'''ldr r4, seed_ptr
bl {base + 0x820}
{'movs r4,#0' if clobber else 'nop'}
movs r0,#0
mov r1,r6
ldr r2,[r4]
bl {base + 0x800}
bx lr
.align 2
seed_ptr: .word {base + 0x3020}
''', base + 0x100)
                data[0x100:0x100 + len(code)] = code
                graph = ThumbGraph(Driver(bytes(data)), base + 0x100, base + 0x300)
                call = next(c for c in graph.calls if c['target'] == base + 0x800)
                result = caller_seed_source(graph, call)
                with self.subTest(base=base, clobber=clobber):
                    if clobber:
                        self.assertEqual(result['status'], 'unsupported')
                    else:
                        self.assertEqual(result['source_va'], base + 0x3020)
                        self.assertIn('callee-saved', result['status'])

    def test_entry_relative_contract_relocates_and_never_grants_plaintext(self):
        for base in (0x10000, 0x430000):
            with self.subTest(base=base):
                contract = crypto_fixture(base)
                self.assertEqual(contract['status'], 'checked entry-relative Open CFB contract')
                self.assertEqual(contract['active_state_va'], base + 0x3020)
                self.assertEqual(contract['encrypted_flag']['encrypted_marker'], 0x12345678)
                self.assertEqual(contract['key_derivation']['table_va'], base + 0x960)
                self.assertEqual(contract['key_derivation']['table_index_bounds'], [-15, 15])
                self.assertFalse(contract['plaintext_at_hook_proved'])
                self.assertFalse(contract['generation_allowed'])
                self.assertIn('inactive', contract['blocker'])

    def test_crypto_guards_payload_key_iv_and_stack_mutations_refuse_contract(self):
        changes = [
            ('bgt gate', 'bge gate'), ('ble exit', 'blt exit'),
            ('beq flag_check', 'beq decrypt'), ('beq exit', 'beq decrypt'),
            ('mov r7,r2', 'mov r7,r3'), ('cmp r3,#1', 'cmp r2,#1'),
            ('ldr r0,[r4,#0x10]', 'ldr r0,[r4,#0xc]'),
            ('mov r1,r0', 'mov r1,r4'), ('strb r3,[r5,#9]', 'strb r3,[r5,#8]'),
            ('.word 0x8000000f', '.word 0x0000000f'),
            ('cmp r1,#0x10', 'cmp r1,#0xf'),
            ('ittt lt\naddlt.w r3,r3,#-1\nornlt r3,r3,#0xf\naddlt r3,#1',
             'ittt mi\naddmi.w r3,r3,#-1\nornmi r3,r3,#0xf\naddmi r3,#1'),
            ('stm.w sp,{r5,r6,r8}', 'stm.w sp,{r5,r6,r7}'),
            ('movs r1,#0x80', 'movs r1,#0xc0'),
            ('subs r3,r0,r3', 'subs r3,r0,r2'),
            (f'table_ptr: .word {0x430960}', f'table_ptr: .word {0x433020}'),
        ]
        for change in changes:
            with self.subTest(change=change):
                self.assertEqual(crypto_fixture(change=change)['status'], 'unsupported')
        self.assertEqual(crypto_fixture(import_change='AES_cbc_encrypt')['status'], 'unsupported')


if __name__ == '__main__':
    unittest.main()
