import os
import socket
import time

# directory to monitor
directory_to_monitor = '/path/to/monitor'

# host and ports to monitor
host = '127.0.0.1'
ports_to_monitor = [80, 443, 22]

# store file and directory info
file_info = {}
dir_info = {}

# log suspicious activities
def log_activity(message):
    with open('log.txt', 'a') as log_file:
        log_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")

def check_for_file_changes(directory):
    global file_info
    global dir_info

    # check files
    for root, dirs, files in os.walk(directory):
        # exclude certain directories
        dirs[:] = [d for d in dirs if d not in ('Library', 'Applications', 'Public') and not d.startswith('.')]
        
        for filename in files:
            if filename == ".zsh_history" or filename == "log.txt":
                continue
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

    # check for new directories
    for root, dirs, _ in os.walk(directory):
        # exclude certain directories
        dirs[:] = [d for d in dirs if d not in ('Library', 'Applications', 'Public') and not d.startswith('.')]
        for dir_name in dirs:
            dir_path = os.path.join(root, dir_name)
            if dir_path not in dir_info:
                dir_info[dir_path] = os.path.exists(dir_path)
                log_activity(f"New directory detected: {dir_path}")

    # check for deleted directories
    for dir in dir_info.copy():
        if not os.path.exists(dir):
            log_activity(f"Directory deleted: {dir}")
            del dir_info[dir]

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

            time.sleep(5)
    except KeyboardInterrupt:
        print("IDS terminated")
