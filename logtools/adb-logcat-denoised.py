#!/usr/bin/env python3.4

import colorama
from colorama import Fore

from common_adb_utils import *

# hardcoded configuration
filter_out_tags = [b'wpa_supplicant']

known_short = set()
known_medium = set()
known_pid = set()
known_tid = set()

def line_uniques(line_bytes, entry, entry_hash_hex, process_table):
    global known_short, known_medium, known_pid, known_tid
    # filters
    if entry['log_tag'] in filter_out_tags:
        return

    entry_pid = entry['process_id']
    entry_tid = entry['process_thread_id']

    # recolor new lines to Green, old messages from new processes with Cyan, and the rest stays White
    message_short = entry['log_level'].decode() + ' ' + entry['log_tag'].decode() + '  ' + entry['log_message'].decode()
    message_medium = str(entry_pid) + '  ' + str(entry_tid) + '  ' + message_short
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

    # add one additional color layer on new PID/TIDs
    message_colored = color + entry['date'].decode() + ' '
    if entry_pid not in known_pid:
        message_colored += Fore.LIGHTWHITE_EX + str(entry_pid).rjust(5) + color
        known_pid.add(entry_pid)
    else:
        message_colored += str(entry_pid).rjust(5)
    message_colored += ' '
    if entry_tid not in known_tid:
        message_colored += Fore.LIGHTWHITE_EX + str(entry_tid).rjust(5) + color
        known_tid.add(entry_tid)
    else:
        message_colored += str(entry_tid).rjust(5)
    message_colored += ' '
    message_colored += message_short
    print(color + message_colored)


colorama.init()
serial = adb_get_first_device_serial()
process_table = adb_get_process_table_snapshot(serial)
adb_logcat_clear(serial)
adb_logcat_parse_lines_sync(serial, line_uniques, process_table)
