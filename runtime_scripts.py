"""Derive the two vendor startup scripts from the user's pinned stock image."""
from pathlib import Path

from firmware import sha256

HERE = Path(__file__).resolve().parent
START = './script/start_main_service.sh'
DAEMON = './script/phone_link_deamon.sh'
LAUNCH = './script/c10_start_androidauto_972.sh'
INIT = './script/c10_capture_init.sh'
LOGGER = './script/c10_usb_capture.sh'
PROVENANCE = './script/c10_autokit_fix.baseline'
BASELINE = b'c10-autokit-fix:2025.10.15.1127:stock\n'
STAGED = './tmp/c10_native_driver'
DRIVER = '/usr/sbin/ARMadb-driver'
DRIVER_MEMBER = '.' + DRIVER
STOCK_SHA = '24589f1b71b95d87379ee2a10e130e939cd45c28bcd3ec328499f5bbd2bc477e'
PACKED_SHA = '614fa754065dcecd7465bfdc283d551abdc0c1d630c9c0c76b520a4272867cdb'
PATCHED_SHA = '0bed061a46ab214b2fa4c3b57c548e01e1f9a814f56295962035153651114d95'
PINS = {
    START: 'e3940344a98c3e4a7321b11eab98d7b5c2a980500215b25f0812896b34c6ed83',
    DAEMON: '39e259a10da4623cd577f927c812efe966a5befa37ae4b1d164cd9d85bc678f8',
    LAUNCH: '47e383b6f7601d64214e7d70fd515ee59e0f26fedf6e9b7fa71a9476f19baf14',
    INIT: '3c1c5c2d4f13e20cd6a899173a2975e2b1a2c46287fd67791ba499ed0b0b8261',
    LOGGER: '412a062a3937c69e59ec570939c60d116026a673cd132d47ebace116b1f8a326',
}


def replace_once(data, before, after):
    if data.count(before) != 1:
        raise ValueError('Stock startup anchor is missing or ambiguous')
    return data.replace(before, after)


def runtime(stock):
    anchor = b'#run custom init shell\n'
    hook = b'test -x /script/c10_capture_init.sh && /script/c10_capture_init.sh\n'
    start = replace_once(stock[START], anchor, hook + b'\n' + anchor)
    start = replace_once(start, b'\tif [ -e /etc/log_com ]; then', b'''\tif [ "$processName" = ARMadb-driver ]; then
\t\tif [ -e /tmp/c10_usb_diagnostics.enabled ]; then
\t\t\t$processName >> /tmp/c10_driver.log 2>&1 &
\t\telse
\t\t\t$processName >> /dev/null 2>&1 &
\t\tfi
\telif [ -e /etc/log_com ]; then''')
    daemon = replace_once(stock[DAEMON], b'\t\t\tARMAndroidAuto\n', b'''\t\t\tif [ -e /tmp/c10_usb_diagnostics.enabled ]; then
\t\t\t\t/script/c10_start_androidauto_972.sh >> /tmp/c10_androidauto.log 2>&1
\t\t\telse
\t\t\t\t/script/c10_start_androidauto_972.sh >> /dev/null 2>&1
\t\t\tfi
''')
    # Keep a deterministic archive order.
    scripts = {START: start}
    for name in (INIT, LOGGER):
        scripts[name] = (HERE / 'runtime' / Path(name).name).read_bytes()
    scripts[DAEMON] = daemon
    scripts[LAUNCH] = (HERE / 'runtime' / Path(LAUNCH).name).read_bytes()
    for name, data in scripts.items():
        if sha256(data) != PINS[name]:
            raise ValueError(f'C10 AutoKit Fix runtime bytes differ from the reference: {name}')
    return scripts
