# client/client_main.py
# Runs the client connection and command session.

import socket       # client TCP connect
import sys          # launcher exit codes
import getpass      # hidden password prompts
from client.commands import ClientSession                       # high-level client session API
from analysis.performance_eval import PerfRecorder, timed       # session metrics

#### Constants ####
USAGE = (
    "Commands:\n"
    "  passwd                            Change your password\n"
    "  upload <local_path> [remote]      Upload a file (stub)\n"
    "  download <remote> [local]         Download a file (stub)\n"
    "  delete <remote_path>              Delete a file (stub)\n"
    "  dir [subpath]                     List directory (stub)\n"
    "  subfolder <create|delete> <path>  Manage subfolders (stub)\n"
    "  admin-adduser <user> <role>       Add a user (admin)\n"
    "  admin-deluser <user>              Delete a user (admin)\n"
    "  admin-setrole <user> <role>       Change a user's role (admin)\n"
    "  admin-resetpass <user>            Reset a user's password (admin)\n"
    "  admin-listusers                   List users (admin)\n"
    "  logout                            Logout and re-login\n"
    "  help                              Show this help\n"
    "  quit / exit                       Logout and exit\n"
)

#### Interactive Setup ####
def _prompt_server_target():
    """
    Prompt you for server IP and port.
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

def _initial_auth(session):
    """
    Run initial login after TCP connection.

    Prompts:
        user: <username>
        pass: <password hidden>
    """
    while True:
        if not session.connected:
            print("[i] Connecting to server...")
            session.connect()
            if not session.connected:
                print("[x] Could not connect to server.")
                return False

        print("--- Login ---")
        username = input("user: ").strip()
        if not username:
            print("[x] Username cannot be empty.")
            continue

        password = getpass.getpass("pass: ")
        ok = session.auth(username, password)
        if ok:
            return True

        choice = input("Authentication failed. Try again? [y/N]: ").strip().lower()
        if choice not in ("y", "yes"):
            return False

#### Command handlers ####
def _handle_passwd(session):
    """
    Handle 'passwd' command for changing your password.
    """
    if not session.authenticated:
        print("[!] You must authenticate first.")
        return

    old_pwd = getpass.getpass("Old password: ")
    new_pwd = getpass.getpass("New password: ")
    confirm = getpass.getpass("Confirm new password: ")

    if new_pwd != confirm:
        print("[x] New passwords do not match.")
        return

    session.change_password(old_pwd, new_pwd)

def _handle_admin_adduser(session, parts):
    """
    Handle admin-adduser command.
    """
    if len(parts) != 3:
        print("Use: admin-adduser <username> <role>")
        return

    username = parts[1]
    role = parts[2]
    pwd = getpass.getpass(f"New password for '{username}': ")
    confirm = getpass.getpass("Confirm password: ")
    if pwd != confirm:
        print("[x] Passwords do not match.")
        return

    session.admin_adduser(username, role, pwd)

def _handle_admin_deluser(session, parts):
    """
    Handle admin-deluser command.
    """
    if len(parts) != 2:
        print("Use: admin-deluser <username>")
        return
    session.admin_deluser(parts[1])

def _handle_admin_setrole(session, parts):
    """
    Handle admin-setrole command.
    """
    if len(parts) != 3:
        print("Use: admin-setrole <username> <role>")
        return
    session.admin_setrole(parts[1], parts[2])

def _handle_admin_resetpass(session, parts):
    """
    Handle admin-resetpass command.
    """
    if len(parts) != 2:
        print("Use: admin-resetpass <username>")
        return
    username = parts[1]
    new_pwd = getpass.getpass(f"New password for '{username}': ")
    confirm = getpass.getpass("Confirm password: ")
    if new_pwd != confirm:
        print("[x] Passwords do not match.")
        return
    session.admin_resetpass(username, new_pwd)

def _handle_logout(session):
    """
    Handle 'logout' command.

    Steps:
      - Send LOGOUT and close current connection.
      - Prompt for a new username/password and attempt re-auth.
      - Return True to keep the client running, False to exit.
    """
    session.logout()
    print("")
    if _initial_auth(session):
        print("Re-authenticated. Type 'help' for commands. Type 'quit' to exit.\n")
        return True

    print("[i] Logout complete. No new authentication requested.")
    return False

def _dispatch(session, line):
    """
    Parse user input and execute the corresponding ClientSession method.
    Returns False to terminate the loop; True to continue.
    """
    if not line:
        return True

    parts = line.split()
    cmd = parts[0].lower()

    # Quit / exit: logout and exit client
    if cmd in ("quit", "exit"):
        session.logout()
        return False

    # Logout: close current session, then re-login
    if cmd == "logout":
        return _handle_logout(session)

    # Help
    if cmd == "help":
        print(USAGE)
        return True

    # Change password
    if cmd == "passwd":
        _handle_passwd(session)
        return True

    # Upload file (stub)
    if cmd == "upload":
        if len(parts) >= 2:
            local_path = parts[1]
            remote_name = parts[2] if len(parts) >= 3 else None
            session.upload(local_path, remote_name)
        else:
            print("Use: upload <local_path> [remote]")
        return True

    # Download file (stub)
    if cmd == "download":
        if len(parts) >= 2:
            remote_name = parts[1]
            local_path = parts[2] if len(parts) >= 3 else None
            session.download(remote_name, local_path)
        else:
            print("Use: download <remote> [local]")
        return True

    # Delete file (stub)
    if cmd == "delete":
        if len(parts) == 2:
            session.delete(parts[1])
        else:
            print("Use: delete <remote_path>")
        return True

    # Directory listing (stub)
    if cmd == "dir":
        subpath = parts[1] if len(parts) >= 2 else None
        session.dir_list(subpath)
        return True

    # Subfolder create/delete (stub)
    if cmd == "subfolder":
        if len(parts) >= 3:
            action = parts[1].lower()
            path = " ".join(parts[2:])
            session.subfolder(action, path)
        else:
            print("Use: subfolder <create|delete> <path>")
        return True

    # Admin commands
    if cmd == "admin-adduser":
        _handle_admin_adduser(session, parts)
        return True

    if cmd == "admin-deluser":
        _handle_admin_deluser(session, parts)
        return True

    if cmd == "admin-setrole":
        _handle_admin_setrole(session, parts)
        return True

    if cmd == "admin-resetpass":
        _handle_admin_resetpass(session, parts)
        return True

    if cmd == "admin-listusers":
        session.admin_listusers()
        return True

    print("Unknown or malformed command. Type 'help'.")
    return True

#### Main Entry Point ####
def main():
    """Main entry point for the client program."""
    server_ip, server_port = _prompt_server_target()

    # Local performance recorder for the client session lifetime
    perf = PerfRecorder()

    # Initialize client session
    session = ClientSession(server_ip, server_port)
    timer = timed()  # Track session duration

    # Connect once; _initial_auth will reconnect if connection drops later
    session.connect()
    if not session.connected:
        print("[x] Could not establish connection. Returning to main menu.\n")
        return False

    # Initial login
    if not _initial_auth(session):
        session.close()
        print("[x] Authentication failed. Returning to main menu.\n")
        elapsed = timer()
        perf.record_response(operation="client_session", seconds=elapsed, source="client")
        return False

    print("Connected and authenticated. Type 'help' for commands.\n")

    # Interactive loop
    try:
        while True:
            try:
                prompt_user = session.username or "guest"
                prompt_role = session.role or "none"
                line = input(f"[{prompt_user}@{prompt_role}]> ").strip()
            except EOFError:
                line = "quit"
            except KeyboardInterrupt:
                print("\n[i] Interrupted.")
                line = "quit"

            try:
                keep_running = _dispatch(session, line)
            except (socket.error, OSError) as e:
                print(f"Network error: {e}")
                keep_running = False

            if not keep_running:
                break

    finally:
        elapsed = timer()
        perf.record_response(operation="client_session", seconds=elapsed, source="client")
        session.close()
        print(f"Disconnected from server. Session duration: {elapsed:.2f}s\n")

    return True  # Indicate normal exit for main.py

#### Run as Script ####
if __name__ == "__main__":
    main()