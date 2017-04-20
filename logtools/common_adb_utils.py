import hashlib
import re as regexp
import subprocess

MODULE_DEBUG = False
adb_exec = b'adb'
adb_serial = None


def adb_set_executable(adb_file_path):
    global adb_exec
    adb_exec = adb_file_path


def adb_get_first_device_serial():
    global adb_exec, adb_serial
    process = subprocess.Popen(adb_exec + b' devices', shell=True, stdout=subprocess.PIPE)
    reLog = regexp.compile(b'^(\w*)\s*device$')
    for line in process.stdout:
        match = reLog.match(line)
        if match is not None:
            serial = match.group(1)
            break
    try:
        print('Selected ADB serial: ' + serial.decode())
        adb_serial=serial
        return serial
    except NameError:
        print('No ADB device found.')
        exit(1)


def adb_get_process_table_snapshot(serial, include_threads=True):
    global MODULE_DEBUG, adb_exec
    extra_args = b' -t' if include_threads else b''
    process = subprocess.Popen(adb_exec + b' -s ' + serial + b' shell ps' + extra_args, shell=True, stdout=subprocess.PIPE)
    rePs = regexp.compile(
        b'^([\w]+)\s+([\d]+)\s+([\d]+)\s+([\d]+)\s+([\d]+)\s+([\w\d]*)\s+([0-9a-fA-F]+)\s+(\w)\s+([\S]+)$')
    processes = {}
    for line in process.stdout:
        if line == '' and process.poll() is not None:
            break
        # parse into 7 tokens, skip incomplete strings
        match = rePs.match(line)
        if match is None or len(match.groups()) != 9:
            if MODULE_DEBUG:
                print(b'skipping ps line: ' + line)
            continue
        tokens = match.groups()
        pid = int(tokens[1])
        processes[pid] = {
            'user_id': tokens[0],
            'pid': pid,
            'parent_pid': int(tokens[2]),
            'vm_size': int(tokens[3]),
            'rs_size': int(tokens[4]),
            'wait_fn': tokens[5],
            'pc': tokens[6],
            'status': tokens[7],
            'name': tokens[8]
        }
    return processes


def adb_logcat_clear(serial):
    global adb_exec
    process = subprocess.Popen(adb_exec + b' -s ' + serial + b' logcat -c', shell=True, stdout=subprocess.PIPE)
    process.wait()


def adb_logcat_parse_lines_sync(serial, line_processing_function, process_table=None):
    global MODULE_DEBUG, adb_exec
    process = subprocess.Popen(adb_exec + b' -s ' + serial + b' logcat --format=year', shell=True, stdout=subprocess.PIPE)
    reLog = regexp.compile(b'^([\d-]+)\s+([.:\d]+)\s+(\d+)\s+(\d+)\s+(\w+)\s([^:]+):(.*)$')
    for line in process.stdout:
        if line == '' and process.poll() is not None:
            break

        # parse into 7 tokens, skip incomplete strings
        match = reLog.match(line)
        if match is None:
            print(b'skipping line: ' + line)
            continue
        tokens = match.groups()
        if len(tokens) != 7:
            print(b'skipping tokens: ' + line)
            continue

        # compute line hash (they will be different because of time)
        entry_hash_hex = hashlib.md5(serial + line).hexdigest()

        # create and index the JSON structure
        log_pid = int(tokens[2])
        entry = {
            'device_serial': serial,
            'date': tokens[0] + b'T' + tokens[1] + b'Z',
            'process_id': log_pid,
            'process_thread_id': int(tokens[3]),
            'log_level': tokens[4],
            'log_tag': tokens[5],
            'log_message': tokens[6].strip()
        }
        # integrate with the process information
        if process_table is not None and log_pid in process_table:
            entry['process'] = process_table[log_pid]
        else:
            if MODULE_DEBUG:
                print(b'unknown process info for: ' + line)
            entry['process'] = {
                'pid': log_pid,
                '_comment': 'process missing from the process_table'
            }

        # call the processor
        if line_processing_function is not None:
            line_processing_function(line, entry, entry_hash_hex, process_table)
        else:
            print('no processing defined for: ' + line.decode("utf-8"))
