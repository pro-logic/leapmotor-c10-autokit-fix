"""Restricted stock-derived shell launch/control-flow analysis and rewrites.

Whole-script hashes identify audit inputs; they never select a version. Only a
checked shell grammar is rewritten, and every other byte comes from that input.
This module emits no archive and grants no native or installation capability.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
import shlex

from firmware import sha256
from runtime_scripts import PINS

HERE = Path(__file__).resolve().parent
START = 'script/start_main_service.sh'
DAEMON = 'script/phone_link_deamon.sh'
INIT = 'script/c10_capture_init.sh'
LAUNCH = 'script/c10_start_androidauto_972.sh'
LOGGER = 'script/c10_usb_capture.sh'


def need(condition, message):
    if not condition:
        raise ValueError(message)


def tokens(code):
    quote, escaped = None, False
    for index, character in enumerate(code):
        if escaped:
            escaped = False
            continue
        if character == '\\' and quote != "'":
            escaped = True
        elif character in ("'", '"', '`'):
            if quote is None:
                quote = character
            elif quote == character:
                quote = None
        elif character == '#' and quote is None and (index == 0 or code[index - 1].isspace()):
            code = code[:index]
            break
    lexer = shlex.shlex(code, posix=True, punctuation_chars=';&|()<>')
    lexer.whitespace_split = True
    lexer.commenters = ''
    try:
        return tuple(lexer)
    except ValueError as error:
        raise ValueError('Unsupported shell quoting') from error


@dataclass
class Node:
    kind: str
    head: tuple
    start: int
    end: int
    body: list = field(default_factory=list)
    branches: list = field(default_factory=list)

    def walk(self):
        yield self
        for item in self.body:
            yield from item.walk()
        for _, items in self.branches:
            for item in items:
                yield from item.walk()


class Shell:
    """Bounded line-oriented shell subset with real compound nesting.

    Supported compound keywords must occupy their observed logical-line forms;
    inline controls, here documents, dynamic evaluation and nested definitions
    are refused. Ordinary commands are opaque, with their external contracts
    explicitly outside this static analysis.
    """
    def __init__(self, data):
        need(isinstance(data, bytes) and 0 < len(data) <= 65536 and b'\0' not in data,
             'Unsupported shell input bounds')
        try:
            text = data.decode('utf-8')
        except UnicodeDecodeError as error:
            raise ValueError('Shell is not UTF-8') from error
        need(not any(ord(c) < 32 and c not in '\t\r\n' for c in text), 'Unsupported shell control byte')
        self.data, self.lines = data, []
        offset, pending, begin = 0, '', 0
        for raw in text.splitlines(keepends=True):
            if not pending:
                begin = offset
            offset += len(raw.encode('utf-8'))
            code = raw.rstrip('\r\n')
            if code.endswith('\\'):
                pending += code[:-1] + ' '
                continue
            code = pending + code
            pending = ''
            ts = tokens(code)
            if ts:
                need('$(' not in code, 'Command/arithmetic substitution outside supported stock grammar')
                substitutions = re.findall(r'`([^`]*)`', code)
                need(len(substitutions) * 2 == code.count('`') and
                     all(part in ('date +%T', 'cat /tmp/update_status') for part in substitutions),
                     'Unsupported backtick command substitution')
                self.lines.append((code.strip(), ts, begin, offset))
        need(not pending, 'Dangling shell continuation')
        need(len(self.lines) <= 2048, 'Shell statement budget exceeded')
        self.index = 0
        self.nodes = self._body(set(), 0)
        need(self.index == len(self.lines), 'Unconsumed shell control')
        self.functions = {}
        for node in self.nodes:
            if node.kind == 'function':
                need(node.head[0] not in self.functions, 'Duplicate shell function')
                self.functions[node.head[0]] = node
        for node in self.nodes:
            for child in node.walk():
                if child.kind == 'function':
                    need(child is node, 'Nested shell function unsupported')
                if child.kind == 'atom':
                    need(not any(t in ('eval', 'source', '.', 'trap', 'exec', '<<', '<<<') for t in child.head),
                         'Dynamic evaluation, traps, exec or here-document unsupported')
                    need(child.head[0] not in ('sh', 'bash', 'dash', 'ksh', 'env', 'command', 'builtin'),
                         'Indirect shell command dispatch unsupported')

    def _body(self, stops, depth):
        need(depth <= 16, 'Shell nesting budget exceeded')
        result = []
        while self.index < len(self.lines):
            code, ts, begin, end = self.lines[self.index]
            if ts[0] in stops or ('arm' in stops and re.fullmatch(r'[A-Za-z0-9_*|]+\)', code)):
                break
            self.index += 1
            function = re.fullmatch(r'([A-Za-z_][A-Za-z_0-9]*)\(\)\s*\{', code)
            if function:
                body = self._body({'}'}, depth + 1)
                end = self._close('}')
                result.append(Node('function', (function[1],), begin, end, body))
            elif code.startswith('if '):
                need(ts[-2:] == (';', 'then'), 'Unsupported if syntax')
                branches = []
                condition = ts[1:-2]
                while True:
                    body = self._body({'elif', 'else', 'fi'}, depth + 1)
                    branches.append((condition, body))
                    need(self.index < len(self.lines), 'Unterminated if')
                    _, next_tokens, _, end = self.lines[self.index]
                    self.index += 1
                    if next_tokens[0] == 'elif':
                        need(next_tokens[-2:] == (';', 'then'), 'Unsupported elif syntax')
                        condition = next_tokens[1:-2]
                    elif next_tokens == ('else',):
                        branches.append((None, self._body({'fi'}, depth + 1)))
                        end = self._close('fi')
                        break
                    else:
                        need(next_tokens == ('fi',), 'Unsupported if close')
                        break
                result.append(Node('if', (), begin, end, branches=branches))
            elif code.startswith('case '):
                need(len(ts) == 3 and ts[-1] == 'in', 'Unsupported case syntax')
                arms = []
                while self.index < len(self.lines):
                    arm, arm_tokens, _, end = self.lines[self.index]
                    self.index += 1
                    if arm_tokens == ('esac',):
                        break
                    need(re.fullmatch(r'[A-Za-z0-9_*|]+\)', arm), 'Unsupported case arm')
                    body = self._body({';;', 'esac', 'arm'}, depth + 1)
                    end = self._close(';;')
                    arms.append(((arm[:-1],), body))
                else:
                    raise ValueError('Unterminated case')
                need(len({a[0] for a, _ in arms}) == len(arms), 'Duplicate case arm')
                result.append(Node('case', ts[1:2], begin, end, branches=arms))
            elif code.startswith('while '):
                need(ts[-1] != 'do', 'Inline while unsupported')
                self._close('do')
                body = self._body({'done'}, depth + 1)
                end = self._close('done')
                result.append(Node('while', ts[1:], begin, end, body))
            else:
                need(ts[0] not in ('fi', 'elif', 'else', 'esac', 'done', 'do', '}', 'for', 'until', 'select', 'function')
                     and '()' not in code and ';;' not in ts, 'Unsupported/misnested shell compound')
                result.append(Node('atom', ts, begin, end))
        return result

    def _close(self, word):
        need(self.index < len(self.lines) and self.lines[self.index][1] == (word,), 'Missing shell ' + word)
        end = self.lines[self.index][3]
        self.index += 1
        return end


def atom(node, source):
    return node.kind == 'atom' and node.head == tokens(source)


def atoms(nodes, expected):
    return len(nodes) == len(expected) and all(atom(n, s) for n, s in zip(nodes, expected))


def echo(node):
    return node.kind == 'atom' and len(node.head) == 2 and node.head[0] == 'echo' and not any(
        c in node.head[1] for c in ('`', '$(', ';', '\n'))


def condition(node, expected):
    return node.kind == 'if' and len(node.branches) == len(expected) and all(
        actual == (tokens(wanted) if wanted is not None else None)
        for (actual, _), wanted in zip(node.branches, expected))


def _start(source):
    shell = Shell(source)
    need(len(shell.functions) == 1, 'Main startup requires one launch helper')
    gates = [n for n in shell.nodes if condition(n, ['[ -e /usr/sbin/ARMadb-driver ]'])]
    need(len(gates) == 1 and len(gates[0].branches[0][1]) == 1, 'Need unique top-level native-driver gate')
    call = gates[0].branches[0][1][0]
    need(call.kind == 'atom' and len(call.head) == 2 and call.head[1] == 'ARMadb-driver'
         and call.head[0] in shell.functions, 'Native-driver gate must call a known helper')
    helper = shell.functions[call.head[0]]
    body = helper.body
    need(len(body) == 4 and atoms(body[:2], ['processName=$1', 'cp /usr/sbin/$processName /tmp/bin/']),
         'Unsupported main launch helper prologue')
    need(condition(body[2], ['[ -e /tmp/UDiskPassThroughMode ]']) and
         len(body[2].branches[0][1]) == 2 and echo(body[2].branches[0][1][0]) and
         atom(body[2].branches[0][1][1], 'return'), 'Native passthrough early return differs')
    log = body[3]
    need(condition(log, ['[ -e /etc/log_com ]', '[ -e /etc/log_file ]', None]), 'Unsupported native logging branch')
    console, file, quiet = [b for _, b in log.branches]
    need(atoms(console, ['$processName 2>&1 | tee -a /tmp/userspace.log &']) and
         atoms(quiet, ['$processName >> /dev/null 2>&1 &']) and len(file) == 1 and
         condition(file[0], ['[ $ttylog -eq 1 ]', None]) and
         atoms(file[0].branches[0][1], ['$processName &']) and
         atoms(file[0].branches[1][1], ['$processName >> /tmp/userspace.log 2>&1 &']),
         'Native logging launches differ')
    custom = [n for n in shell.nodes if atom(n, 'test -e /script/custom_init.sh && /script/custom_init.sh')]
    need(len(custom) == 1 and helper.end <= custom[0].start < gates[0].start,
         'Need unique top-level custom-init point preceding driver startup')
    for node in shell.nodes:
        if node.kind == 'function':
            continue
        for child in node.walk():
            if child.kind == 'atom':
                need(not any(t in ('exit', 'return', 'break', 'continue') for t in child.head),
                     'Top-level main transfer can bypass initialization/launch')
                need(not child.head[0].startswith('$') and
                     (not any(t.rsplit('/', 1)[-1] == 'ARMadb-driver' for t in child.head) or child is call),
                     'Additional or indirect native-driver launch unsupported')
    calls = [n for n in sum([list(n.walk()) for n in shell.nodes], []) if n.kind == 'atom'
             and n.head and n.head[0] == helper.head[0]]
    need(calls == [call], 'Additional main launch helper call unsupported')
    return shell, helper, log, custom[0], gates[0]


def _case(node, variable):
    need(node.kind == 'case' and node.head == (variable,), 'Unsupported link dispatch case')
    result = {head[0]: body for head, body in node.branches}
    need(set(result) in ({'CarPlay', 'AndroidAuto', 'HiCar', 'ICCOA'},
                         {'CarPlay', 'AndroidAuto', 'HiCar', 'ICCOA', 'CarLife'}), 'Unsupported link case alternatives')
    return result


def _daemon(source):
    shell = Shell(source)
    expected_names = {'Usage', 'CheckPhoneLinkFile', 'CopyPhoneLinkFile', 'RunLinkProcess', 'EndLinkProcess',
                      'WaitLinkDeamonExited', 'StartLinkDeamon', 'StopLinkDeamon', 'RestartLinkDeamon'}
    need(set(shell.functions) == expected_names, 'Unsupported link daemon function set')
    functions = shell.functions
    root = [n for n in shell.nodes if n.kind != 'function']
    need(len(root) == 6 and condition(root[0], ['[ $# -ne 2 ]']) and
         atoms(root[0].branches[0][1], ['Usage']) and
         atoms(root[1:5], ['linktype=$1', 'action=$2', 'lockfile=/tmp/.${linktype}_daemon_started',
                           'exitfile=/tmp/.${linktype}_daemon_exited']), 'Unsupported daemon argument/lock setup')
    action = root[5]
    need(action.kind == 'case' and action.head == ('$action',) and
         [h for h, _ in action.branches] == [('start',), ('stop',), ('restart',), ('*',)] and
         all(atoms(body, [target]) for (_, body), target in zip(action.branches,
             ('StartLinkDeamon', 'StopLinkDeamon', 'RestartLinkDeamon', 'Usage'))), 'Unsupported daemon action routing')
    need(len(functions['Usage'].body) == 2 and echo(functions['Usage'].body[0]) and
         atom(functions['Usage'].body[1], 'exit 1'), 'Unsupported daemon usage function')
    run = functions['RunLinkProcess']
    need(len(run.body) == 1, 'Unexpected run-link statements')
    cases = _case(run.body[0], '$linktype')
    programs = {'CarPlay': 'ARMiPhoneIAP2', 'AndroidAuto': 'ARMAndroidAuto',
                'HiCar': 'ARMHiCar', 'ICCOA': 'iccoa', 'CarLife': 'CarLife'}
    for role, body in cases.items():
        if role != 'AndroidAuto':
            need(atoms(body, [programs[role]]), 'Unexpected non-AA launch branch')
    aa = cases['AndroidAuto']
    hfpd = 'ps |grep -v grep|grep hfpd || hfpd -y -E -f &'
    need(len(aa) == 2 and atom(aa[1], 'ARMAndroidAuto'), 'AA must be the final synchronous branch command')
    if aa[0].kind == 'if':
        need(condition(aa[0], ['[ -e /tmp/.bluetoothDaemon_init_done ]']) and
             atoms(aa[0].branches[0][1], [hfpd]), 'Unsupported Bluetooth readiness guard')
        bluetooth = 'readiness-marker gated'
    else:
        need(atom(aa[0], hfpd), 'Unsupported hfpd launch')
        bluetooth = 'unconditional vendor prelude'
    start = functions['StartLinkDeamon'].body
    optional = atom(start[1], 'test -e $exitfile && (rm -f $exitfile;echo "Continue Run Link Deamon: $linktype")')
    if optional:
        start = start[:1] + start[2:]
    need(len(start) == 11 and atoms(start[:3], ['CheckPhoneLinkFile', 'test -e $lockfile && exit 0', 'touch $lockfile'])
         and echo(start[3]) and atoms(start[4:6], ['WaitLinkDeamonExited', 'CopyPhoneLinkFile']),
         'Unsupported daemon start ordering')
    loop = start[6]
    need(loop.kind == 'while' and loop.head == tokens('[ -e $lockfile ]') and len(loop.body) == 3,
         'Unsupported daemon session loop')
    guard = loop.body[0]
    need(condition(guard, ['[ -e /sys/class/net/wlan0/address ] && [ ! -e /sys/class/bluetooth/hci0/address ]',
                          "[ -e /tmp/update_status ] && [ `cat /tmp/update_status` != '4' ]", None]),
         'Unsupported daemon readiness/update guard')
    waiting, updating, launch = [b for _, b in guard.branches]
    need(len(waiting) == 1 and echo(waiting[0]) and len(updating) == 3 and echo(updating[0]) and
         atoms(updating[1:], ['rm -f $lockfile', 'break']) and atoms(launch, ['RunLinkProcess']) and
         atoms(loop.body[1:], ['test -e $exitfile && break', 'test -e $lockfile && sleep 1']) and
         echo(start[7]) and atoms(start[8:], ['rm -f $exitfile', 'rm -f $lockfile', 'exit 0']),
         'Unsupported daemon loop cleanup or launch control')
    # The role boundaries and untouched functions are bound by hashes. Read-only
    # checks ensure the persistent AA executable is required/copied before Run.
    check = functions['CheckPhoneLinkFile'].body
    need(len(check) == 1, 'Unexpected executable-presence statements')
    presence = _case(check[0], '$linktype')
    persistent = dict(programs, CarPlay='AppleCarPlay')
    need(set(presence) == set(cases) and all(atoms(body, [f'test -e /usr/sbin/{persistent[role]} || exit 1'])
         for role, body in presence.items()), 'Executable presence gates differ')
    copy = functions['CopyPhoneLinkFile'].body
    need(len(copy) == 4 and atoms(copy[:2], ['tmpLibPath=/tmp/lib/', 'tmpBinPath=/tmp/bin/']) and
         atom(copy[3], 'sync'), 'Unsupported link copy/sync setup')
    copied = _case(copy[2], '$linktype')
    copy_commands = {
        'CarPlay': 'cp /usr/sbin/AppleCarPlay $tmpBinPath; cp /usr/sbin/ARMiPhoneIAP2 $tmpBinPath;',
        'AndroidAuto': 'cp /usr/sbin/ARMAndroidAuto $tmpBinPath; cp /usr/sbin/hfpd $tmpBinPath; cp -d /usr/lib/libssl.so* $tmpLibPath;',
        'HiCar': 'cp /usr/sbin/ARMHiCar $tmpBinPath; cp /usr/lib/libdmsdp* $tmpLibPath; cp /usr/lib/libHisightSink.so $tmpLibPath;'
                 ' cp /usr/lib/libHwDeviceAuthSDK.so $tmpLibPath; cp /usr/lib/libHwKeystoreSDK.so $tmpLibPath;'
                 ' cp /usr/lib/libmanagement.so $tmpLibPath; cp /usr/lib/libsecurec.so $tmpLibPath;'
                 ' cp /usr/lib/libauthagent.so $tmpLibPath; cp /usr/lib/libnearby.so $tmpLibPath; cp /usr/lib/libhicar.so $tmpLibPath',
        'ICCOA': 'cp /usr/sbin/iccoa $tmpBinPath; cp -d /usr/lib/libcarlink.so $tmpLibPath;',
        'CarLife': 'cp /usr/sbin/CarLife $tmpBinPath;',
    }
    need(set(copied) == set(cases) and all(atoms(body, [f'test -e $tmpBinPath/{persistent[role]} || ({copy_commands[role]} )'])
         for role, body in copied.items()), 'Link RAM-copy control differs')
    end = functions['EndLinkProcess'].body
    need(len(end) == 1, 'Unexpected end-link statements')
    endings = _case(end[0], '$linktype')
    need(set(endings) == set(cases), 'End-link alternatives differ')
    for role, body in endings.items():
        if role == 'CarPlay':
            need(atoms(body, ['killall ARMiPhoneIAP2', 'killall AppleCarPlay']), 'CarPlay stop differs')
        elif role == 'AndroidAuto':
            need(atoms(body, ['killall hfpd', 'killall ARMAndroidAuto']) or atoms(body,
                 ['killall hfpd', 'ps |grep -v grep|grep hfpd && sleep 1', 'killall ARMAndroidAuto']), 'AA stop differs')
        else:
            need(atoms(body, ['killall ' + programs[role]]), 'Non-AA stop differs')
    calls = [n for node in shell.nodes for n in node.walk() if n.kind == 'atom' and n.head and n.head[0] == 'ARMAndroidAuto']
    need(calls == [aa[1]], 'Additional raw AA launch unsupported')
    run_calls = [n for node in shell.nodes for n in node.walk() if n.kind == 'atom' and n.head and n.head[0] == 'RunLinkProcess']
    need(run_calls == launch, 'Additional run-link invocation unsupported')
    wait = functions['WaitLinkDeamonExited'].body
    need(len(wait) == 1 and wait[0].kind == 'while' and wait[0].head == tokens('[ -e $exitfile ]') and
         len(wait[0].body) == 3 and echo(wait[0].body[0]) and
         atoms(wait[0].body[1:], ['sleep 0.1', 'EndLinkProcess']), 'Exit-wait contract differs')
    for name in ('StopLinkDeamon', 'RestartLinkDeamon'):
        body = functions[name].body
        need(len(body) == 2 and condition(body[0], ['[ -e $lockfile ]']) and atom(body[1], 'exit 0'),
             'Stop/restart control differs')
        actions = body[0].branches[0][1]
        expected = ['touch $exitfile', 'EndLinkProcess', 'WaitLinkDeamonExited'] if name == 'StopLinkDeamon' else ['EndLinkProcess']
        need(len(actions) == len(expected) + 1 and echo(actions[0]) and atoms(actions[1:], expected),
             'Stop/restart actions differ')
    return shell, aa[1], bluetooth, optional


def analyze_runtime(files):
    """Require an understood launch grammar; unsupported scripts raise ValueError."""
    start, helper, log, custom, gate = _start(files[START])
    daemon, aa, bluetooth, cancel_exit = _daemon(files[DAEMON])
    return dict(schema='c10-stock-runtime-contract-v1', status='checked restricted shell launch/control-flow grammar',
                stock_script_sha256={name: sha256(files[name]) for name in (START, DAEMON)},
                main=dict(function=helper.head[0], ram_copy_before_launch=True,
                    passthrough_returns_without_launch=True, custom_init_precedes_driver=True,
                    initializer_insert_offset=custom.start, logger_edit_range=[log.start, log.end],
                    driver_gate_range=[gate.start, gate.end]),
                android_auto=dict(launch_range=[aa.start, aa.end], synchronous=True,
                    file_check_and_ram_copy_before_session=True, session_lock_and_update_guard=True,
                    bluetooth=bluetooth, cancels_pending_exit_on_start=cancel_exit),
                assumptions=['external vendor commands and executables obey their normal shell contracts',
                    'global boot/session serialization is provided by the stock caller; not established here',
                    'runtime helper semantics require separate Linux shell validation'],
                generation_allowed=False, installable_images_emitted=False)


def derive_runtime(files):
    """Return stock-specific scripts/helpers in memory, with exact edit provenance."""
    evidence = analyze_runtime(files)
    start, daemon = files[START], files[DAEMON]
    newline = b'\r\n' if b'\r\n' in start else b'\n'
    lo, hi = evidence['main']['logger_edit_range']
    before = start[lo:hi]
    indentation = re.match(rb'[ \t]*', before).group()
    prefix = indentation + b'if [ "$processName" = ARMadb-driver ]; then\n' + indentation + b'\tif [ -e /tmp/c10_usb_diagnostics.enabled ]; then\n' + indentation + b'\t\t$processName >> /tmp/c10_driver.log 2>&1 &\n' + indentation + b'\telse\n' + indentation + b'\t\t$processName >> /dev/null 2>&1 &\n' + indentation + b'\tfi\n'
    prefix = prefix.replace(b'\n', newline)
    replacement = prefix + before.replace(indentation + b'if ', indentation + b'elif ', 1)
    insert = evidence['main']['initializer_insert_offset']
    hook = b'test -x /script/c10_capture_init.sh && /script/c10_capture_init.sh' + newline
    # Descending source offsets avoid rebasing any audited range.
    edits = [(lo, hi, replacement), (insert, insert, hook)]
    for begin, end, after in sorted(edits, reverse=True):
        start = start[:begin] + after + start[end:]
    lo, hi = evidence['android_auto']['launch_range']
    before = daemon[lo:hi]
    indentation = re.match(rb'[ \t]*', before).group()
    newline = b'\r\n' if b'\r\n' in daemon else b'\n'
    replacement = (indentation + b'if [ -e /tmp/c10_usb_diagnostics.enabled ]; then\n' + indentation + b'\t/script/c10_start_androidauto_972.sh >> /tmp/c10_androidauto.log 2>&1\n' + indentation + b'else\n' + indentation + b'\t/script/c10_start_androidauto_972.sh >> /dev/null 2>&1\n' + indentation + b'fi\n').replace(b'\n', newline)
    daemon = daemon[:lo] + replacement + daemon[hi:]
    scripts = {START: start, DAEMON: daemon}
    for name in (INIT, LAUNCH, LOGGER):
        content = (HERE / 'runtime' / Path(name).name).read_bytes()
        need(sha256(content) == PINS['./' + name], 'Runtime helper source differs from validated reference')
        scripts[name] = content
    evidence['derived_script_sha256'] = {name: sha256(body) for name, body in scripts.items()}
    evidence['edits'] = [dict(member=START, source_range=[begin, end], before_sha256=sha256(files[START][begin:end]),
                              after_bytes=len(after), after_sha256=sha256(after)) for begin, end, after in edits] + [
        dict(member=DAEMON, source_range=[lo, hi], before_sha256=sha256(files[DAEMON][lo:hi]),
             after_bytes=len(replacement), after_sha256=sha256(replacement))]
    evidence['preservation'] = 'All bytes outside the three declared edits are copied from this exact stock input; rollback must retain these exact original scripts'
    return scripts, evidence
