# client/commands.py
# Processes user input and client commands.

import os           # local file paths
import socket       # TCP client socket
import threading    # sync reads and writes
import json         # auth/admin payload encoding
from cryptography.fernet import Fernet                          # encrypt auth and admin payloads
from analysis.performance_eval import PerfRecorder, timed       # client-side metrics

import requests ## used to deal with uploads from computer

#### Constants ####
BUFFER = 64 * 1024   # 64KB buffer size for file transfer
ENC = "utf-8"        # Encoding format for strings
LINE_END = b"\n"     # Line ending byte sequence
CLIENT_SECRET_KEY_FILE = "server/storage/database/auth_secret.key"  # Must match server's key file

#### Encryption helpers ####
def _load_shared_key():
    """
    Load the shared Fernet key used for auth and admin payloads.

    Returns:
        bytes | None: Key bytes if available, otherwise None.
    """
    if not os.path.exists(CLIENT_SECRET_KEY_FILE):
        print(f"[auth] Shared key file '{CLIENT_SECRET_KEY_FILE}' not found.")
        print("[auth] Copy this key file from the server host before running the client.")
        return None

    with open(CLIENT_SECRET_KEY_FILE, "rb") as f:
        key = f.read().strip()

    if not key:
        print("[auth] Shared key file is empty.")
        return None

    return key

def _get_cipher():
    """
    Create a Fernet cipher instance using the shared key.

    Returns:
        Fernet | None: Cipher object, or None if the key cannot be loaded.
    """
    key = _load_shared_key()
    if key is None:
        return None

    try:
        return Fernet(key)
    except Exception as exc:
        print(f"[auth] Could not create cipher: {exc}")
        return None

def encrypt_payload(payload_dict):
    """
    Encrypt a small JSON payload for transit.

    Parameters:
        payload_dict (dict): Data to JSON-encode and encrypt.

    Returns:
        str | None: Base64 token string on success, or None on error.
    """
    cipher = _get_cipher()
    if cipher is None:
        return None

    try:
        raw = json.dumps(payload_dict).encode(ENC)
        token = cipher.encrypt(raw)
        return token.decode(ENC)
    except Exception as exc:
        print(f"[auth] Encryption failed: {exc}")
        return None

#### Client session ####
class ClientSession:
    """
    High-level client session wrapper for one TCP connection.

    Tracks:
      - Server address (ip, port)
      - Socket object and connection state
      - Authenticated username, user_id, and role
      - Client-side performance metrics
    """

    def __init__(self, ip, port):
        self.addr = (ip, port)              # Server (ip, port)
        self.sock = None                    # Active socket
        self._recv_lock = threading.Lock()  # Serialize reads
        self._send_lock = threading.Lock()  # Serialize writes
        self.connected = False              # TCP connection flag
        self.username = None                # Authenticated username
        self.user_id = None                 # Server-assigned user id
        self.role = None                    # 'user' or 'admin'
        self.authenticated = False          # Auth status
        self.perf = PerfRecorder()          # Local performance recorder

    #### Basic Helpers ####
    def _sendline(self, line):
        """
        Send a single line to the server, appending a newline.
        """
        if not self.sock:
            print("[!] No active connection.")
            return
        data = (line.rstrip("\n") + "\n").encode(ENC)
        with self._send_lock:
            self.sock.sendall(data)
        # Placeholder: add client-side logging of outbound commands.

    def _readline(self):
        """
        Read a single newline-terminated line from the server.

        Returns:
            str | None: Line text without the newline, or None on EOF.
        """
        if not self.sock:
            return None

        buf = bytearray()
        with self._recv_lock:
            while True:
                ch = self.sock.recv(1)
                if not ch:
                    break
                buf += ch
                if ch == LINE_END:
                    break

        if not buf:
            return None

        return buf[:-1].decode(ENC, errors="replace")
        # Placeholder: add timeout handling and more robust framing if needed.

    #### Connection Lifecycle ####
    def connect(self):
        """
        Open a TCP connection to the configured server address.

        Returns:
            bool: True on success, False on failure.
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            print(f"[+] Connecting to {self.addr[0]}:{self.addr[1]} ...")
            self.sock.connect(self.addr)
            self.sock.settimeout(5)
            self.connected = True
            print("[i] TCP connection established.\n")
            return True
        except ConnectionRefusedError:
            print(f"[x] Connection refused. No server listening at {self.addr}.")
        except socket.timeout:
            print("[x] Connection timed out.")
        except OSError as e:
            print(f"[x] Connection error: {e}")

        self.close()
        return False

    def logout(self):
        """
        Send a LOGOUT command and close the connection.
        """
        if not self.connected or not self.sock:
            print("[!] Not connected to a server.")
            return
        try:
            self._sendline("LOGOUT")
            resp = self._readline()
            if resp is None:
                print("[i] Logout request sent (no response).")
            else:
                print(f"[server] {resp}")
        except (OSError, socket.error) as e:
            print(f"[x] Error sending logout: {e}")
        finally:
            self.close()

    def close(self):
        """
        Safely close the socket and reset session state.
        """
        if self.sock:
            try:
                self.sock.close()
                print("[i] Connection closed.")
            except Exception:
                pass
        self.sock = None
        self.connected = False
        self.authenticated = False
        self.username = None
        self.user_id = None
        self.role = None
        # Placeholder: dump or summarize client-side metrics using self.perf.snapshot().

    #### Authentication and account commands ####
    def auth(self, username, password):
        """
        Authenticate with the server using an encrypted AUTH payload.

        Returns:
            bool: True if authentication succeeds, False otherwise.
        """
        if not self.connected or not self.sock:
            print("[!] Not connected; cannot authenticate.")
            return False

        payload = {
            "op": "login",
            "username": username,
            "password": password,
        }

        token = encrypt_payload(payload)
        if token is None:
            print("[x] Could not build encrypted auth payload.")
            return False

        timer = timed()
        self._sendline(f"AUTH {token}")
        resp = self._readline()
        duration = timer()
        self.perf.record_response(operation="auth", seconds=duration, source="client")

        if resp is None:
            print("[x] No response from server during auth.")
            self.close()
            return False

        parts = resp.split()
        if len(parts) >= 2 and parts[0] == "OK" and parts[1] == "AUTH":
            # Expected format: OK AUTH role=<role> user_id=<user_id>
            role = None
            user_id = None
            for piece in parts[2:]:
                if piece.startswith("role="):
                    role = piece.split("=", 1)[1]
                elif piece.startswith("user_id="):
                    user_id = piece.split("=", 1)[1]

            self.username = username
            self.role = role
            self.user_id = user_id
            self.authenticated = True
            print(f"[i] Authenticated as '{self.username}' (role={self.role}, id={self.user_id}).")
            return True

        if len(parts) >= 2 and parts[0] == "ERR" and parts[1] == "AUTH":
            reason = " ".join(parts[2:]) if len(parts) > 2 else "unknown error"
            print(f"[x] Authentication failed: {reason}")
        else:
            print(f"[x] Unexpected auth response: {resp}")

        self.close()
        return False

    def change_password(self, old_password, new_password):
        """
        Change the current user's password via the PASSWD command.
        """
        if not self.authenticated:
            print("[!] You must authenticate before changing password.")
            return

        payload = {
            "op": "passwd",
            "old_password": old_password,
            "new_password": new_password,
        }

        token = encrypt_payload(payload)
        if token is None:
            print("[x] Could not build encrypted password payload.")
            return

        timer = timed()
        self._sendline(f"PASSWD {token}")
        resp = self._readline()
        duration = timer()
        self.perf.record_response(operation="passwd", seconds=duration, source="client")

        if resp is None:
            print("[x] No response for PASSWD command.")
            return

        parts = resp.split()
        if len(parts) >= 2 and parts[0] == "OK" and parts[1] == "PASSWD":
            print("[i] Password changed.")
        elif len(parts) >= 2 and parts[0] == "ERR" and parts[1] == "PASSWD":
            reason = " ".join(parts[2:]) if len(parts) > 2 else "unknown error"
            print(f"[x] PASSWD failed: {reason}")
        else:
            print(f"[x] Unexpected PASSWD response: {resp}")

    #### Admin commands ####
    def _check_admin(self, cmd_name):
        """
        Verify that the current session is authenticated as an admin.

        Returns:
            bool: True if the admin command is allowed, False otherwise.
        """
        if self.role != "admin":
            print(f"[!] {cmd_name} denied: not logged in as admin.")
            return False
        if not self.authenticated:
            print(f"[!] {cmd_name} denied: not authenticated.")
            return False
        return True

    def admin_adduser(self, username, role, password):
        """
        Send an ADMIN ADDUSER command to create a new user.
        """
        if not self._check_admin("ADMIN ADDUSER"):
            return

        payload = {
            "op": "adduser",
            "password": password,
        }
        token = encrypt_payload(payload)
        if token is None:
            print("[x] Could not build encrypted ADDUSER payload.")
            return

        line = f"ADMIN ADDUSER {username} {role} {token}"
        timer = timed()
        self._sendline(line)
        resp = self._readline()
        duration = timer()
        self.perf.record_response(operation="admin_adduser", seconds=duration, source="client")

        if resp is None:
            print("[x] No response for ADMIN ADDUSER.")
            return

        parts = resp.split()
        if len(parts) >= 3 and parts[0] == "OK" and parts[1] == "ADMIN" and parts[2] == "ADDUSER":
            print(f"[i] Added user '{username}' with role '{role}'.")
        elif len(parts) >= 2 and parts[0] == "ERR" and parts[1] == "ADMIN":
            reason = " ".join(parts[2:]) if len(parts) > 2 else "unknown error"
            print(f"[x] ADMIN ADDUSER failed: {reason}")
        else:
            print(f"[x] Unexpected ADMIN ADDUSER response: {resp}")

    def admin_deluser(self, username):
        """
        Send an ADMIN DELUSER command to remove a user.
        """
        if not self._check_admin("ADMIN DELUSER"):
            return

        line = f"ADMIN DELUSER {username}"
        timer = timed()
        self._sendline(line)
        resp = self._readline()
        duration = timer()
        self.perf.record_response(operation="admin_deluser", seconds=duration, source="client")

        if resp is None:
            print("[x] No response for ADMIN DELUSER.")
            return

        parts = resp.split()
        if len(parts) >= 3 and parts[0] == "OK" and parts[1] == "ADMIN" and parts[2] == "DELUSER":
            print(f"[i] Deleted user '{username}'.")
        elif len(parts) >= 2 and parts[0] == "ERR" and parts[1] == "ADMIN":
            reason = " ".join(parts[2:]) if len(parts) > 2 else "unknown error"
            print(f"[x] ADMIN DELUSER failed: {reason}")
        else:
            print(f"[x] Unexpected ADMIN DELUSER response: {resp}")

    def admin_setrole(self, username, role):
        """
        Send an ADMIN SETROLE command to change a user's role.
        """
        if not self._check_admin("ADMIN SETROLE"):
            return

        line = f"ADMIN SETROLE {username} {role}"
        timer = timed()
        self._sendline(line)
        resp = self._readline()
        duration = timer()
        self.perf.record_response(operation="admin_setrole", seconds=duration, source="client")

        if resp is None:
            print("[x] No response for ADMIN SETROLE.")
            return

        parts = resp.split()
        if len(parts) >= 4 and parts[0] == "OK" and parts[1] == "ADMIN" and parts[2] == "SETROLE":
            print(f"[i] Set role for '{username}' to '{role}'.")
        elif len(parts) >= 2 and parts[0] == "ERR" and parts[1] == "ADMIN":
            reason = " ".join(parts[2:]) if len(parts) > 2 else "unknown error"
            print(f"[x] ADMIN SETROLE failed: {reason}")
        else:
            print(f"[x] Unexpected ADMIN SETROLE response: {resp}")

    def admin_resetpass(self, username, new_password):
        """
        Send an ADMIN RESETPASS command to set a new password for a user.
        """
        if not self._check_admin("ADMIN RESETPASS"):
            return

        payload = {
            "op": "resetpass",
            "new_password": new_password,
        }
        token = encrypt_payload(payload)
        if token is None:
            print("[x] Could not build encrypted RESETPASS payload.")
            return

        line = f"ADMIN RESETPASS {username} {token}"
        timer = timed()
        self._sendline(line)
        resp = self._readline()
        duration = timer()
        self.perf.record_response(operation="admin_resetpass", seconds=duration, source="client")

        if resp is None:
            print("[x] No response for ADMIN RESETPASS.")
            return

        parts = resp.split()
        if len(parts) >= 3 and parts[0] == "OK" and parts[1] == "ADMIN" and parts[2] == "RESETPASS":
            print(f"[i] Reset password for '{username}'.")
        elif len(parts) >= 2 and parts[0] == "ERR" and parts[1] == "ADMIN":
            reason = " ".join(parts[2:]) if len(parts) > 2 else "unknown error"
            print(f"[x] ADMIN RESETPASS failed: {reason}")
        else:
            print(f"[x] Unexpected ADMIN RESETPASS response: {resp}")

    def admin_listusers(self):
        """
        Send an ADMIN LISTUSERS command and print the returned user list.
        """
        if not self._check_admin("ADMIN LISTUSERS"):
            return

        timer = timed()
        self._sendline("ADMIN LISTUSERS")
        first_line = self._readline()
        duration = timer()
        self.perf.record_response(operation="admin_listusers", seconds=duration, source="client")

        if first_line is None:
            print("[x] No response for ADMIN LISTUSERS.")
            return

        if first_line.strip() != "OK ADMIN LISTUSERS BEGIN":
            print(f"[x] Unexpected response: {first_line}")
            return

        print("[i] Users:")
        while True:
            line = self._readline()
            if line is None:
                print("[x] ADMIN LISTUSERS ended unexpectedly.")
                return
            if line.strip() == "OK ADMIN LISTUSERS END":
                break
            # Each line: "<username> <role> <user_id>"
            print(f"  {line}")

    #### File and directory commands (left for teammates) ####
    def dir_list(self, path=None):
        """
        Request a directory listing from the server via the DIR command.
        """
        if not self.authenticated:
            print("[!] Authenticate before using DIR.")
            return

        line = "DIR" if not path else f"DIR {path}"
        timer = timed()
        self._sendline(line)
        resp = self._readline()
        duration = timer()
        self.perf.record_response(operation="dir", seconds=duration, source="client")

        # Placeholder: handle listing output (single or multiple lines).
        if resp is None:
            print("[x] No response for DIR.")
            return
        print(f"[server] {resp}")

    def delete(self, remote_path):
        """
        Request deletion of a remote file via the DELETE command.
        """
        if not self.authenticated:
            print("[!] Authenticate before using DELETE.")
            return

        timer = timed()
        self._sendline(f"DELETE {remote_path}")
        resp = self._readline()
        duration = timer()
        self.perf.record_response(operation="delete", seconds=duration, source="client")

        # Placeholder: handle server confirmation or error.
        if resp is None:
            print("[x] No response for DELETE.")
            return
        print(f"[server] {resp}")

    def subfolder(self, action, path):
        """
        Manage remote subfolders using the SUBFOLDER command.
        """
        if not self.authenticated:
            print("[!] Authenticate before using SUBFOLDER.")
            return

        action = action.lower()
        if action not in ("create", "delete"):
            print("[x] SUBFOLDER action must be 'create' or 'delete'.")
            return

        timer = timed()
        self._sendline(f"SUBFOLDER {action} {path}")
        resp = self._readline()
        duration = timer()
        self.perf.record_response(operation="subfolder", seconds=duration, source="client")

        # Placeholder: handle server confirmation.
        if resp is None:
            print("[x] No response for SUBFOLDER.")
            return
        print(f"[server] {resp}")

    def upload(self, local_path, remote_name=None):
        """
        Request an upload of a local file to the server via the UPLOAD command.
        """
       ##checks if the file is authenticated
        if not self.authenticated:
            print("[!] Authenticate before using UPLOAD.")
            return

        ###checks if the file is in the system
        if not os.path.exists(local_path):
            print(f"[x] Local file '{local_path}' not found.")
            return
        if not os.path.isfile(local_path):
            print(f"[x] '{local_path}' is not a file.")
            return


        filename = remote_name if remote_name else os.path.basename(local_path)
        file_size = os.path.getsize(local_path)

        ### send handshake, waits for READY
        # Protocol: UPLOAD <filename> <size>
        print(f"[i] Requesting upload: {filename} ({file_size} bytes)...")
        self._sendline(f"UPLOAD {filename} {file_size}")


        ##HANDLES cases where the transmission is terminated.

        try:

            resp = self._readline()

            if resp is None:

                print("[x] Connection closed by server during handshake.")

                return

            if resp != "READY":

                print(f"[x] Server rejected upload request. Reason: {resp}")

                return

        except Exception as e:

            print(f"[x] Error during handshake: {e}")

            return

        ## start the server transmission with CHUNKS of data
        print("[i] Sending file data...")
        timer = timed()
        sent_bytes = 0

        try:
            with open(local_path, "rb") as f:
                while True:
                    chunk = f.read(BUFFER)
                    if not chunk:
                        break

                    # Acquire lock to ensure no other thread writes to socket simultaneously
                    with self._send_lock:
                        self.sock.sendall(chunk)

                    sent_bytes += len(chunk)

            ## record the performance.
            duration = timer()
            self.perf.record_transfer(
                operation="upload",
                bytes_count=sent_bytes,
                seconds=duration,
                source="client"
            )

            if sent_bytes != file_size:
                print(f"[!] Warning: File size changed during upload. Sent {sent_bytes}/{file_size}.")

            ## wait for final ACK
            final_resp = self._readline()
            if final_resp and final_resp.startswith("OK"):
                print(f"[i] Upload complete. Server response: {final_resp}")

            else:

                print(f"[x] Upload may have failed. Server response: {final_resp}")

        except OSError as e:

            print(f"[x] Network error during transmission: {e}")

            self.close()

        except Exception as e:

            print(f"[x] Unexpected error: {e}")

    def download(self, remote_name, local_path=None):
        """
        Request a download of a remote file from the server via the DOWNLOAD command.
        """
        if not self.authenticated:
            print("[!] Authenticate before using DOWNLOAD.")
            return

        local_target = local_path if local_path else remote_name


        timer = timed()
        self._sendline(f"DOWNLOAD {remote_name}")
        # Placeholder: receive file size and file data, write to local_target.
        resp = self._readline()

        # Placeholder: replace bytes_count=0 with actual file size once implemented.

        if resp is None:

            print("[x] No response for DOWNLOAD.")

            return



        parts = resp.split()

        if len(parts) != 2 or parts[0] != "SIZE":

            print(f"[x] Server rejected download. Response: {resp}")

            return

        try:

            file_size = int(parts[1])

        except ValueError:

            print(f"[x] Invalid file size received: {parts[1]}")

            return

        print(f"[i] Receiving '{remote_name}' ({file_size} bytes) to '{local_target}'...")

        # 3. Send READY acknowledgement
        # This tells the server to start streaming the binary data.
        self._sendline("READY")

        # 4. Receive File Data
        received_bytes = 0

        try:
            with open(local_target, "wb") as f:

                while received_bytes < file_size:

                    # Calculate how much to read, limiting to the buffer size

                    to_read = min(BUFFER, file_size - received_bytes)

                    chunk = self.sock.recv(to_read)

                    if not chunk:

                        print("[x] Connection closed by server mid-transfer.")

                        break

                    f.write(chunk)

                    received_bytes += len(chunk)

            # 5. Check final size and record metrics

            duration = timer()

            self.perf.record_transfer(operation="download", bytes_count=received_bytes, seconds=duration, source="client")

            if received_bytes == file_size:

                print(f"[i] Download complete: {received_bytes} bytes written.")

            else:

                print(f"[x] Download incomplete! Expected {file_size} bytes, received {received_bytes} bytes.")

        except Exception as e:

            print(f"[x] Error receiving or writing file: {e}")

