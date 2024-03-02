import os
import socket
import time

# directory to monitor
directory_to_monitor = '/path/to/monitor'

# host and ports to monitor
host = '127.0.0.1'
ports_to_monitor = [80, 443, 22]

file_info = {} # dictionary to store file information

# log suspicious activities
def log_activity(message):
    with open('log.txt', 'a') as log_file:
        log_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")

# check for file changes
def check_for_file_changes(directory):
    global file_info

    for root, dirs, files in os.walk(directory):
        # exclude certain directories
        dirs[:] = [d for d in dirs if d not in ('Library', 'Applications', 'Public') and not d.startswith('.')]
        
        for filename in files:
            filepath = os.path.join(root, filename)

            if os.path.isfile(filepath):
                if filepath not in file_info:
                    file_info[filepath] = os.stat(filepath).st_mtime
                    log_activity(f"New file detected: {filepath}")
                elif os.stat(filepath).st_mtime != file_info[filepath]:
                    log_activity(f"File {filepath} modified.")
                    file_info[filepath] = os.stat(filepath).st_mtime

    # check for deleted files
    for filepath in list(file_info.keys()):
        if not os.path.exists(filepath):
            log_activity(f"File {filepath} deleted.")
            del file_info[filepath]

# check for open ports
def check_for_open_ports():
    for port in ports_to_monitor:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1) # timeout for connection attempt
            result = s.connect_ex((host, port))

            # check if the port is open
            if result == 0:
                log_activity(f"Port {port} accessed.")
            s.close()
        except socket.error as e:
            log_activity(f"Error: {e}")


if __name__ == "__main__":
    print("IDS started...")
    try:
        while True:
            check_for_file_changes(directory_to_monitor)
            check_for_open_ports()

            time.sleep(30)
    except KeyboardInterrupt:
        print("IDS terminated")
