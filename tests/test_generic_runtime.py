"""Source-generated shell layouts and launch/control-flow adversaries."""
import unittest
from unittest.mock import patch

from generic_runtime import START, DAEMON, Shell, analyze_runtime, derive_runtime, tokens


def fixture(gated=False, windows=False):
    main = '''# synthetic startup fixture: preserve this header
#!/bin/sh
spawn() {
 processName=$1
 cp /usr/sbin/$processName /tmp/bin/
 if [ -e /tmp/UDiskPassThroughMode ]; then
  echo "fixture passthrough"
  return
 fi
 if [ -e /etc/log_com ]; then
  $processName 2>&1 | tee -a /tmp/userspace.log &
 elif [ -e /etc/log_file ]; then
  if [ $ttylog -eq 1 ]; then
   $processName &
  else
   $processName >> /tmp/userspace.log 2>&1 &
  fi
 else
  $processName >> /dev/null 2>&1 &
 fi
}
# different ordering, spacing and unrelated command from either vendor sample
printf 'fixture # literal\\n'
test -e /script/custom_init.sh && /script/custom_init.sh
if [ -e /usr/sbin/ARMadb-driver ]; then
 spawn ARMadb-driver
fi
echo preserved-after-launch
'''
    executable = {'CarPlay': 'AppleCarPlay', 'AndroidAuto': 'ARMAndroidAuto', 'HiCar': 'ARMHiCar', 'ICCOA': 'iccoa'}
    launch = dict(executable, CarPlay='ARMiPhoneIAP2')
    libraries = {
        'CarPlay': [('cp', '/usr/sbin/ARMiPhoneIAP2', '$tmpBinPath')],
        'AndroidAuto': [('cp', '/usr/sbin/hfpd', '$tmpBinPath'), ('cp -d', '/usr/lib/libssl.so*', '$tmpLibPath')],
        'HiCar': [('cp', '/usr/lib/libdmsdp*', '$tmpLibPath')] + [
            ('cp', '/usr/lib/' + name + '.so', '$tmpLibPath') for name in
            ('libHisightSink', 'libHwDeviceAuthSDK', 'libHwKeystoreSDK', 'libmanagement', 'libsecurec', 'libauthagent', 'libnearby', 'libhicar')],
        'ICCOA': [('cp -d', '/usr/lib/libcarlink.so', '$tmpLibPath')],
    }
    def case(arms):
        return 'case $linktype in\n' + ''.join(name + ')\n' + body + '\n;;\n' for name, body in arms.items()) + 'esac\n'
    def function(name, body):
        return name + '() {\n' + body + '}\n'
    source = '# entirely source-generated test daemon\n#!/bin/sh\n'
    source += function('Usage', 'echo "fixture usage"\nexit 1\n')
    source += 'if [ $# -ne 2 ]; then\nUsage\nfi\nlinktype=$1\naction=$2\n'
    source += function('CheckPhoneLinkFile', case({k: f'test -e /usr/sbin/{v} || exit 1' for k, v in executable.items()}))
    copied = {}
    for name, program in executable.items():
        commands = [('cp', '/usr/sbin/' + program, '$tmpBinPath')] + libraries[name]
        code = '; '.join(' '.join(c) for c in commands) + (';' if name != 'HiCar' else '')
        copied[name] = f'test -e $tmpBinPath/{program} || ({code} )'
    source += function('CopyPhoneLinkFile', 'tmpLibPath=/tmp/lib/\ntmpBinPath=/tmp/bin/\n' + case(copied) + 'sync\n')
    prelude = 'ps |grep -v grep|grep hfpd || hfpd -y -E -f &\n'
    if gated:
        prelude = 'if [ -e /tmp/.bluetoothDaemon_init_done ]; then\n' + prelude + 'fi\n'
    source += function('RunLinkProcess', case({name: prelude + program if name == 'AndroidAuto' else program
                                             for name, program in launch.items()}))
    ends = {k: 'killall ' + v for k, v in launch.items()}
    ends['CarPlay'] += '\nkillall AppleCarPlay'
    ends['AndroidAuto'] = 'killall hfpd\nkillall ARMAndroidAuto'
    source += function('EndLinkProcess', case(ends))
    source += 'lockfile=/tmp/.${linktype}_daemon_started\nexitfile=/tmp/.${linktype}_daemon_exited\n'
    source += function('WaitLinkDeamonExited', 'while [ -e $exitfile ]\ndo\necho "fixture waiting"\nsleep 0.1\nEndLinkProcess\ndone\n')
    source += function('StartLinkDeamon', '''CheckPhoneLinkFile
test -e $lockfile && exit 0
touch $lockfile
echo "fixture start"
WaitLinkDeamonExited
CopyPhoneLinkFile
while [ -e $lockfile ]
do
 if [ -e /sys/class/net/wlan0/address ] && [ ! -e /sys/class/bluetooth/hci0/address ]; then
  echo "fixture Bluetooth wait"
 elif [ -e /tmp/update_status ] && [ `cat /tmp/update_status` != '4' ]; then
  echo "fixture update"
  rm -f $lockfile
  break
 else
  RunLinkProcess
 fi
 test -e $exitfile && break
 test -e $lockfile && sleep 1
done
echo "fixture done"
rm -f $exitfile
rm -f $lockfile
exit 0
''')
    source += function('StopLinkDeamon', 'if [ -e $lockfile ]; then\necho "fixture stop"\ntouch $exitfile\nEndLinkProcess\nWaitLinkDeamonExited\nfi\nexit 0\n')
    source += function('RestartLinkDeamon', 'if [ -e $lockfile ]; then\necho "fixture restart"\nEndLinkProcess\nfi\nexit 0\n')
    source += 'case $action in\nstart)\nStartLinkDeamon\n;;\nstop)\nStopLinkDeamon\n;;\nrestart)\nRestartLinkDeamon\n;;\n*)\nUsage\n;;\nesac\n'
    data = {START: main.encode(), DAEMON: source.encode()}
    return {k: v.replace(b'\n', b'\r\n') for k, v in data.items()} if windows else data


class RuntimeGrammarTests(unittest.TestCase):
    def test_both_bluetooth_shapes_and_source_line_endings_derive_exactly_three_edits(self):
        for gated in (False, True):
            for windows in (False, True):
                source = fixture(gated, windows)
                scripts, report = derive_runtime(source)
                self.assertEqual(report['main']['function'], 'spawn')
                self.assertEqual(len(report['edits']), 3)
                self.assertFalse(report['generation_allowed'])
                self.assertIn(b'# synthetic startup fixture: preserve this header', scripts[START])
                self.assertTrue(scripts[START].endswith(b'echo preserved-after-launch' + (b'\r\n' if windows else b'\n')))
                self.assertIn(b'killall ARMAndroidAuto', scripts[DAEMON])
                self.assertNotIn(b'\nARMAndroidAuto\n', scripts[DAEMON])
                self.assertIn(b'/script/c10_start_androidauto_972.sh', scripts[DAEMON])
                for name in (START, DAEMON):
                    Shell(scripts[name])
                self.assertEqual(report['android_auto']['bluetooth'], 'readiness-marker gated' if gated else 'unconditional vendor prelude')

    def test_main_copy_gate_and_initialization_bypasses_refused(self):
        changes = [
            (b'cp /usr/sbin/$processName /tmp/bin/', b'true'),
            (b'spawn ARMadb-driver', b'spawn OtherDriver'),
            (b'  return\n', b'  true\n'),
            (b'echo preserved-after-launch', b'ARMadb-driver &'),
            (b'echo preserved-after-launch', b'spawn ARMadb-driver'),
            (b'echo preserved-after-launch', b'false || exit 1'),
            (b'echo preserved-after-launch', b'$launch'),
            (b'echo preserved-after-launch', b'echo "$(ARMadb-driver)"'),
            (b'echo preserved-after-launch', b'echo `ARMadb-driver`'),
            (b'echo preserved-after-launch', b'echo x; /tmp/bin/ARMadb-driver &'),
            (b'test -e /script/custom_init.sh && /script/custom_init.sh',
             b'if [ -e /tmp/maybe ]; then\ntest -e /script/custom_init.sh && /script/custom_init.sh\nfi'),
        ]
        for before, after in changes:
            data = fixture()
            data[START] = data[START].replace(before, after)
            with self.subTest(change=after), self.assertRaises(ValueError):
                analyze_runtime(data)

    def test_daemon_background_launch_update_copy_lock_and_action_mutations_refused(self):
        changes = [
            (b'ARMAndroidAuto\n', b'ARMAndroidAuto &\n'),
            (b'RunLinkProcess\n fi', b'RunLinkProcess\n  RunLinkProcess\n fi'),
            (b'CheckPhoneLinkFile\ntest', b'true\ntest'),
            (b'CopyPhoneLinkFile\nwhile', b'RunLinkProcess\nwhile'),
            (b'rm -f $lockfile\n  break', b'true\n  break'),
            (b'start)\nStartLinkDeamon', b'start)\nRunLinkProcess'),
            (b'cp /usr/sbin/ARMAndroidAuto $tmpBinPath', b'cp /usr/sbin/OtherAuto $tmpBinPath'),
            (b'killall ARMAndroidAuto', b'echo foo; ARMAndroidAuto'),
            (b'linktype=$1', b'linktype=$2'),
            (b'echo "fixture usage"', b'echo "$(ARMAndroidAuto)"'),
        ]
        for before, after in changes:
            data = fixture()
            self.assertIn(before, data[DAEMON])
            data[DAEMON] = data[DAEMON].replace(before, after, 1)
            with self.subTest(change=after), self.assertRaises(ValueError):
                analyze_runtime(data)

    def test_shell_nesting_and_dynamic_evaluation_refuse_ambiguous_control(self):
        self.assertEqual(tokens('if [ $# -ne 2 ]; then # comment'), ('if', '[', '$#', '-ne', '2', ']', ';', 'then'))
        self.assertEqual(tokens('echo "literal # data" # comment'), ('echo', 'literal # data'))
        self.assertEqual(len(Shell(b'echo "if"\n').nodes), 1)
        for data in (b'if true; then echo x; fi\n', b'if true; then\necho x\n',
                     b'foo() {\nfoo() {\n}\n}\n', b'foo() {\n}\nfoo() {\n}\n',
                     b'case $x in\na)\necho x\n;&\nesac\n', b'eval "$x"\n', b'sh -c "$x"\n',
                     b'echo value\\', b'cat <<EOF\nx\nEOF\n'):
            with self.subTest(source=data), self.assertRaises(ValueError):
                Shell(data)

    def test_changed_shared_runtime_bytes_are_refused(self):
        with patch('generic_runtime.PINS', {}), self.assertRaises((KeyError, ValueError)):
            derive_runtime(fixture())


if __name__ == '__main__':
    unittest.main()
