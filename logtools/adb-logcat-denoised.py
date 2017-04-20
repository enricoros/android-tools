#!/usr/bin/env python3.4

import colorama
from colorama import Fore

from common_adb_utils import *

# hardcoded configuration
filter_out_tags = [b'wpa_supplicant']

known_short = set()
known_medium = set()


def line_uniques(line_bytes, entry, entry_hash_hex, process_table):
    global known_short, known_medium
    # filters
    if entry['log_tag'] in filter_out_tags:
        return

    # recolor new lines to Green, old messages from new processes with Cyan, and the rest stays White
    message_short = entry['log_level'].decode() + ' ' + entry['log_tag'].decode() + '  ' + entry['log_message'].decode()
    message_medium = str(entry['process_id']) + '  ' + str(entry['process_thread_id']) + '  ' + message_short
    message_full = entry['date'].decode() + ' ' + message_medium
    if message_short in known_short:
        if message_medium in known_medium:
            color = Fore.WHITE
        else:
            known_medium.add(message_medium)
            color = Fore.CYAN
    else:
        known_short.add(message_short)
        known_medium.add(message_medium)
        color = Fore.GREEN if not message_medium.endswith('ms') else Fore.CYAN
    print(color + message_full)


colorama.init()
serial = adb_get_first_device_serial()
process_table = adb_get_process_table_snapshot(serial)
adb_logcat_clear(serial)
adb_logcat_parse_lines_sync(serial, line_uniques, process_table)
