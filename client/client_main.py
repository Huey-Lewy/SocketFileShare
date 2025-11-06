# client/client_main.py
# Runs the client connection and command session.

import socket
import sys
from commands import ClientSession
from analysis.performance_eval import PerfRecorder, timed  # For timing and metric tracking

#### Constants ####
USAGE = (
    "Commands:\n"
    "  auth <username> <password>\n"
    "  upload <local_path>\n"
    "  download <filename>\n"
    "  delete <filename>\n"
    "  dir\n"
    "  subfolder <create|delete> <path>\n"
    "  help\n"
    "  quit\n"
)

#### Interactive Setup ####
def _prompt_server_target():
    """
    Prompt the user for server IP and port interactively.
    Exit if input is invalid.
    """
    print("====== CNT3004 Socket File Sharing Client ======")
    server_ip = input("Enter server IP address: ").strip()
    if not server_ip:
        print("Server IP cannot be empty.")
        sys.exit(1)

    port_str = input("Enter server port: ").strip()
    try:
        server_port = int(port_str)
    except ValueError:
        print("Port must be an integer.")
        sys.exit(1)

    if not (0 <= server_port <= 65535):
        print("Port must be between 0-65535.")
        sys.exit(1)

    return server_ip, server_port

#### Command Dispatch ####
def _dispatch(session, line):
    """
    Parse user input and execute the corresponding ClientSession method.
    Returns False to terminate the loop; True to continue.

    Placeholder: future command validation and progress feedback can be added here.
    """
    if not line:
        return True

    parts = line.split()
    cmd = parts[0].lower()

    # Exit command
    if cmd in ("quit", "exit"):
        session.logout()
        return False

    # Help command
    if cmd == "help":
        print(USAGE)
        return True

    # Authentication command
    if cmd == "auth":
        if len(parts) == 3:
            session.auth(parts[1], parts[2])
        else:
            print("Use: auth <username> <password>")
        return True

    # Upload file
    if cmd == "upload":
        if len(parts) == 2:
            session.upload(parts[1])
        else:
            print("Use: upload <local_path>")
        return True

    # Download file
    if cmd == "download":
        if len(parts) == 2:
            session.download(parts[1])
        else:
            print("Use: download <filename>")
        return True

    # Delete file
    if cmd == "delete":
        if len(parts) == 2:
            session.delete(parts[1])
        else:
            print("Use: delete <filename>")
        return True

    # Directory listing
    if cmd == "dir":
        if len(parts) == 1:
            session.dir_list()
        else:
            print("Use: dir")
        return True

    # Subfolder create/delete
    if cmd == "subfolder":
        if len(parts) >= 3:
            action = parts[1].lower()
            path = " ".join(parts[2:])
            session.subfolder(action, path)
        else:
            print("Use: subfolder <create|delete> <path>")
        return True

    print("Unknown or malformed command. Type 'help'.")
    return True

#### Main Entry Point ####
def main():
    """Main entry point for the client program."""
    server_ip, server_port = _prompt_server_target()

    # Create performance recorder (local per session)
    perf = PerfRecorder()

    # Initialize client session
    session = ClientSession(server_ip, server_port)
    timer = timed()  # Track session duration
    session.connect()

    # Return to launcher if connection fails
    if not session.connected:
        print("[x] Could not establish connection. Returning to main menu.\n")
        return False

    print("Connected. Type 'help' for commands. Type 'quit' to exit.\n")

    # Interactive loop
    try:
        while True:
            try:
                line = input("> ").strip()
            except EOFError:
                line = "quit"
            except KeyboardInterrupt:
                print("\n[i] Interrupted.")
                line = "quit"

            try:
                keep_running = _dispatch(session, line)
            except (socket.error, OSError) as e:
                print(f"Network error: {e}")
                # Placeholder: add reconnection and retry handling if needed.
                keep_running = True

            if not keep_running:
                break

    finally:
        elapsed = timer()
        perf.record_response(operation="client_session", seconds=elapsed)
        session.close()
        print(f"Disconnected from server. Session duration: {elapsed:.2f}s\n")

    return True  # Indicate normal exit for main.py

#### Run as Script ####
if __name__ == "__main__":
    main()
