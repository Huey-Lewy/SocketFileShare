# server/server_main.py
# Starts the multithreaded server application.

import socket                       # TCP server sockets
import threading                    # per-client threads
from datetime import datetime       # timestamps for user logs
from cryptography.fernet import InvalidToken                    # decrypt error type from auth
from analysis.performance_eval import PerfRecorder, timed       # timing and metrics
from server import file_ops     # file commands and storage helpers
from server import auth         # login, users, and roles

#### Constants ####
BUFFER = 64 * 1024  # 64KB buffer size for file transfer
ENC = "utf-8"       # Encoding format for strings
BACKLOG = 5         # Max queued connections

#### Performance Recorder + Client Session Class ####
# Shared globally across client threads
perf = PerfRecorder()

# Holds per-connection state for an authenticated client.
class ClientSession:
    """
    Holds per-connection state for an authenticated client.
    """

    def __init__(self, conn, addr, user_record, storage_root, log_path):
        self.conn = conn
        self.addr = addr
        self.username = user_record.get("username")
        self.user_id = user_record.get("user_id")
        self.role = user_record.get("role", auth.ROLE_USER)
        self.storage_root = storage_root
        self.log_path = log_path
        self.authenticated = True

    def log(self, message):
        """
        Append a timestamped message to this user's log file.
        """
        try:
            ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
            line = f"{ts} [{self.role}:{self.username}] {message}\n"
            file_ops.append_log(self.log_path, line)
        except Exception as exc:
            # Do not break the session if logging fails.
            print(f"[log] Failed to write log for {self.username}: {exc}")

#### Interactive Setup ####
def _prompt_server_config():
    """
    Prompt the user for server IP and port.
    Return (host, port) if valid; return None if invalid input.
    """
    print("====== CNT3004 Socket File Sharing Server ======")
    host = input("Enter server IP address (e.g., 0.0.0.0 or localhost): ").strip()
    if not host:
        print("Server IP cannot be empty.")
        return None

    port_str = input("Enter server port: ").strip()
    try:
        port = int(port_str)
    except ValueError:
        print("Port must be an integer.")
        return None

    if not (0 <= port <= 65535):
        print("Port must be between 0–65535.")
        return None

    return host, port

#### Socket helpers ####
def _recv_line(conn, max_bytes=4096):
    """
    Read a single line (terminated by '\\n') from a socket.

    This protects against partial reads and overly long input.

    Parameters:
        conn (socket.socket): Connected socket.
        max_bytes (int): Hard cap on bytes to read.

    Returns:
        str or None: Line without trailing newline, or None if connection closed.

    Raises:
        ValueError: If input exceeds max_bytes without newline.
    """
    buf = bytearray()
    while len(buf) < max_bytes:
        chunk = conn.recv(1024)
        if not chunk:
            if not buf:
                return None
            break
        buf.extend(chunk)
        if b"\n" in chunk:
            break

    if not buf:
        return None
    if len(buf) >= max_bytes and b"\n" not in buf:
        raise ValueError("Line too long")

    line, _, _ = buf.partition(b"\n")
    return line.decode(ENC, errors="replace").strip()


def _send_line(conn, text):
    """
    Send a single line to the client, appending '\\n'.
    """
    data = (text.rstrip("\n") + "\n").encode(ENC)
    conn.sendall(data)

#### Command helpers ####
def _handle_self_passwd(session, line):
    """
    Handle PASSWD command for the current user.

    Protocol:
        PASSWD <token>

    Where <token> is an encrypted JSON payload:
        {
            "op": "passwd",
            "old_password": "...",
            "new_password": "..."
        }
    """
    parts = line.split(" ", 1)
    if len(parts) != 2:
        _send_line(session.conn, "ERR PASSWD Usage: PASSWD <token>")
        session.log("PASSWD failed: bad syntax")
        return

    token = parts[1].strip()
    try:
        payload = auth.decrypt_payload(token)
    except InvalidToken:
        _send_line(session.conn, "ERR PASSWD Invalid token")
        session.log("PASSWD failed: invalid token")
        return
    except ValueError:
        _send_line(session.conn, "ERR PASSWD Invalid payload")
        session.log("PASSWD failed: invalid payload")
        return

    if payload.get("op") != "passwd":
        _send_line(session.conn, "ERR PASSWD Invalid op")
        session.log("PASSWD failed: invalid op")
        return

    old_pwd = payload.get("old_password")
    new_pwd = payload.get("new_password")
    if not old_pwd or not new_pwd:
        _send_line(session.conn, "ERR PASSWD Missing fields")
        session.log("PASSWD failed: missing fields")
        return

    ok, _ = auth.verify_credentials(session.username, old_pwd)
    if not ok:
        _send_line(session.conn, "ERR PASSWD Invalid old password")
        session.log("PASSWD failed: invalid old password")
        return

    if not auth.reset_password(session.username, new_pwd):
        _send_line(session.conn, "ERR PASSWD Could not reset password")
        session.log("PASSWD failed: reset error")
        return

    _send_line(session.conn, "OK PASSWD Password changed")
    session.log("Password changed")

def _handle_admin_command(session, line):
    """
    Handle ADMIN commands for user management.

    Protocol examples:
        ADMIN ADDUSER <username> <role> <token>
        ADMIN DELUSER <username>
        ADMIN SETROLE <username> <role>
        ADMIN RESETPASS <username> <token>
        ADMIN LISTUSERS
    """
    if session.role != auth.ROLE_ADMIN:
        _send_line(session.conn, "ERR ADMIN Not authorized")
        session.log("ADMIN command denied: not admin")
        return

    parts = line.split()
    if len(parts) < 2:
        _send_line(session.conn, "ERR ADMIN Missing subcommand")
        session.log("ADMIN failed: missing subcommand")
        return

    sub = parts[1].upper()

    if sub == "ADDUSER":
        if len(parts) < 5:
            _send_line(session.conn, "ERR ADMIN Usage: ADMIN ADDUSER <username> <role> <token>")
            session.log("ADMIN ADDUSER failed: bad syntax")
            return
        username = parts[2]
        role = parts[3]
        token = parts[4]

        try:
            payload = auth.decrypt_payload(token)
        except InvalidToken:
            _send_line(session.conn, "ERR ADMIN Invalid token")
            session.log("ADMIN ADDUSER failed: invalid token")
            return
        except ValueError:
            _send_line(session.conn, "ERR ADMIN Invalid payload")
            session.log("ADMIN ADDUSER failed: invalid payload")
            return

        if payload.get("op") != "adduser":
            _send_line(session.conn, "ERR ADMIN Invalid op")
            session.log("ADMIN ADDUSER failed: invalid op")
            return

        password = payload.get("password")
        if not password:
            _send_line(session.conn, "ERR ADMIN Missing password")
            session.log("ADMIN ADDUSER failed: missing password")
            return

        try:
            record = auth.register_user(username, password, role=role)
        except ValueError as exc:
            _send_line(session.conn, f"ERR ADMIN {exc}")
            session.log(f"ADMIN ADDUSER failed: {exc}")
            return

        # Create storage and log paths for the new user
        file_ops.ensure_user_paths(record["role"], record["user_id"])
        _send_line(session.conn, f"OK ADMIN ADDUSER {username}")
        session.log(f"Added user '{username}' with role '{role}'")

    elif sub == "DELUSER":
        if len(parts) != 3:
            _send_line(session.conn, "ERR ADMIN Usage: ADMIN DELUSER <username>")
            session.log("ADMIN DELUSER failed: bad syntax")
            return
        username = parts[2]
        if not auth.delete_user(username):
            _send_line(session.conn, "ERR ADMIN User not found")
            session.log(f"ADMIN DELUSER failed: user '{username}' not found")
            return
        _send_line(session.conn, f"OK ADMIN DELUSER {username}")
        session.log(f"Deleted user '{username}'")

    elif sub == "SETROLE":
        if len(parts) != 4:
            _send_line(session.conn, "ERR ADMIN Usage: ADMIN SETROLE <username> <role>")
            session.log("ADMIN SETROLE failed: bad syntax")
            return
        username = parts[2]
        role = parts[3]
        try:
            if not auth.set_role(username, role):
                _send_line(session.conn, "ERR ADMIN User not found")
                session.log(f"ADMIN SETROLE failed: user '{username}' not found")
                return
        except ValueError as exc:
            _send_line(session.conn, f"ERR ADMIN {exc}")
            session.log(f"ADMIN SETROLE failed: {exc}")
            return

        _send_line(session.conn, f"OK ADMIN SETROLE {username} {role}")
        session.log(f"Set role for '{username}' to '{role}'")

    elif sub == "RESETPASS":
        if len(parts) < 4:
            _send_line(session.conn, "ERR ADMIN Usage: ADMIN RESETPASS <username> <token>")
            session.log("ADMIN RESETPASS failed: bad syntax")
            return
        username = parts[2]
        token = parts[3]

        try:
            payload = auth.decrypt_payload(token)
        except InvalidToken:
            _send_line(session.conn, "ERR ADMIN Invalid token")
            session.log("ADMIN RESETPASS failed: invalid token")
            return
        except ValueError:
            _send_line(session.conn, "ERR ADMIN Invalid payload")
            session.log("ADMIN RESETPASS failed: invalid payload")
            return

        if payload.get("op") != "resetpass":
            _send_line(session.conn, "ERR ADMIN Invalid op")
            session.log("ADMIN RESETPASS failed: invalid op")
            return

        new_pwd = payload.get("new_password")
        if not new_pwd:
            _send_line(session.conn, "ERR ADMIN Missing new password")
            session.log("ADMIN RESETPASS failed: missing new password")
            return

        if not auth.reset_password(username, new_pwd):
            _send_line(session.conn, "ERR ADMIN User not found")
            session.log(f"ADMIN RESETPASS failed: user '{username}' not found")
            return

        _send_line(session.conn, f"OK ADMIN RESETPASS {username}")
        session.log(f"Reset password for '{username}'")

    elif sub == "LISTUSERS":
        users = auth.list_users()
        # Send a simple list: username, role, user_id per line
        _send_line(session.conn, "OK ADMIN LISTUSERS BEGIN")
        for rec in users:
            line = f"{rec.get('username')} {rec.get('role')} {rec.get('user_id')}"
            _send_line(session.conn, line)
        _send_line(session.conn, "OK ADMIN LISTUSERS END")
        session.log("Listed users")

    else:
        _send_line(session.conn, "ERR ADMIN Unknown subcommand")
        session.log(f"ADMIN unknown subcommand: {sub}")

#### Client Handler ####
def handle_client(conn, addr):
    """
    Handle communication with a connected client.
    """
    print(f"[+] New connection from {addr}")
    session_timer = timed()  # Measure total session duration

    session = None

    try:
        # Authentication handshake
        auth_timer = timed()
        ok, user_record = auth.handle_auth(conn, addr)
        auth_latency = auth_timer()
        perf.record_response(operation="auth", seconds=auth_latency)

        if not ok or user_record is None:
            print(f"[auth] Login failed for {addr}")
            return

        role = user_record.get("role", auth.ROLE_USER)
        user_id = user_record.get("user_id", "")
        username = user_record.get("username", "")

        # Prepare user-specific storage and log paths
        storage_root, log_path = file_ops.ensure_user_paths(role, user_id)

        session = ClientSession(conn, addr, user_record, storage_root, log_path)
        session.log("Login successful")
        print(f"[+] Authenticated {username} ({role}, id={user_id}) from {addr}")

        # Main command loop
        while True:
            line = _recv_line(conn)
            if line is None:
                # Client closed the connection
                if session:
                    session.log("Connection closed by client")
                break

            if not line:
                continue

            cmd = line.split()[0].upper()

            if cmd == "LOGOUT":
                _send_line(conn, "OK LOGOUT Goodbye")
                if session:
                    session.log("Logout requested by client")
                break

            elif cmd == "UPLOAD":
                file_ops.handle_upload(session, line, perf)

            elif cmd == "DOWNLOAD":
                file_ops.handle_download(session, line, perf)

            elif cmd == "DELETE":
                file_ops.handle_delete(session, line, perf)

            elif cmd == "DIR":
                file_ops.handle_dir(session, line, perf)

            elif cmd == "SUBFOLDER":
                file_ops.handle_subfolder(session, line, perf)

            elif cmd == "PASSWD":
                _handle_self_passwd(session, line)

            elif cmd == "ADMIN":
                _handle_admin_command(session, line)

            else:
                _send_line(conn, "ERR UNKNOWN Command")
                if session:
                    session.log(f"Unknown command: {line}")

    except ConnectionResetError:
        print(f"[x] Connection reset by {addr}")
        if session:
            session.log("Connection reset by peer")

    except Exception as e:
        print(f"[x] Error with {addr}: {e}")
        if session:
            session.log(f"Server error: {e}")

    finally:
        try:
            conn.close()
        except Exception:
            pass
        elapsed = session_timer()
        perf.record_response(operation="session", seconds=elapsed)
        print(f"[-] Disconnected from {addr} (Session Duration: {elapsed:.2f}s)")
        if session:
            session.log(f"Session ended after {elapsed:.2f}s")

#### Main Entry Point ####
def main():
    """Main entry point for the server."""
    config = _prompt_server_config()
    if not config:
        print("[x] Invalid server configuration. Returning to main menu.\n")
        return False

    host, port = config
    print(f"[i] Starting server on {host}:{port} ...")

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_sock.bind((host, port))
        server_sock.listen(BACKLOG)
        server_sock.settimeout(1.0)  # Allows periodic interrupt checks
    except OSError as e:
        print(f"[x] Failed to start server: {e}")
        return False

    print(f"[✓] Server listening on {host}:{port}\nPress Ctrl+C to stop.\n")

    start_timer = timed()

    try:
        while True:
            try:
                conn, addr = server_sock.accept()
                thread = threading.Thread(
                    target=handle_client, args=(conn, addr), daemon=True
                )
                thread.start()

            except socket.timeout:
                # Keeps loop responsive to interrupts
                continue

            except KeyboardInterrupt:
                print("\n[i] Stopping server...")
                break

    except KeyboardInterrupt:
        print("\n[i] Server interrupted. Stopping...")

    finally:
        server_sock.close()
        uptime = start_timer()
        perf.record_response(operation="server_uptime", seconds=uptime)
        print(f"[i] Server stopped. Total runtime: {uptime:.2f}s\n")
        # Placeholder: Later, perf metrics can be dumped to disk from the analysis module.

    # Return False so main.py menu reloads
    return False

#### Run as Script ####
if __name__ == "__main__":
    main()
