# client/commands.py
# Processes user input and client commands.

import os
import socket
import sys
import threading
import time

BUFFER = 64 * 1024  # 64KB buffer size for file transfer
ENC = 'utf-8'       # Encoding format for strings
LINE_END = b"\n"    # Line ending byte sequence

class ClientSession:
    def __init__(self, ip, port):
        self.addr = (ip, port)              # Tuple holding server address and port
        self.sock = None                    # Active socket connection to the server
        self._recv_lock = threading.Lock()  # Lock to prevent overlapping reads from socket
        self._send_lock = threading.Lock()  # Lock to prevent overlapping writes to socket
        self.connected = False              # Connection status flag
        self.transfer_times = []            # Stores timing and speed data for uploads/downloads

    #### Basic helpers ####
    def _sendline(self, line):
        """Encode and send a single line terminated with newline."""
        if not self.sock:
            print("[!] No active connection.")
            return
        data = (line + "\n").encode(ENC)
        with self._send_lock:
            self.sock.sendall(data)

    def _readline(self):
        """Read a single newline-terminated line; return decoded str without newline."""
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

    #### Connection lifecycle ####
    def connect(self):
        """Attempt to connect to the server; handle connection errors gracefully."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            print(f"[+] Connecting to {self.addr[0]}:{self.addr[1]} ...")
            self.sock.connect(self.addr)
            self.sock.settimeout(5)
            self.connected = True
            print("[✓] Connection established.\n")
        except ConnectionRefusedError:
            print(f"[x] Connection refused. No server listening at {self.addr}.")
            self.close()
        except socket.timeout:
            print(f"[x] Connection timed out.")
            self.close()
        except OSError as e:
            print(f"[x] Connection error: {e}")
            self.close()

    def logout(self):
        """Send logout command and close the connection."""
        if not self.connected or not self.sock:
            print("[!] Not connected to a server.")
            return
        try:
            self._sendline("LOGOUT")
            print("[i] Logout request sent.")
        except (OSError, socket.error) as e:
            print(f"[x] Error sending logout: {e}")
        finally:
            self.close()

    def close(self):
        """Safely close the socket connection."""
        if self.sock:
            try:
                self.sock.close()
                print("[i] Connection closed.")
            except Exception:
                pass
        self.sock = None
        self.connected = False

    #### Commands ####
    def auth(self, username, password):
        """Placeholder for authentication command."""
        self._sendline(f"AUTH {username} {password}")

    def dir_list(self):
        """Placeholder for directory listing."""
        self._sendline("DIR")

    def delete(self, filename):
        """Placeholder for delete command."""
        self._sendline(f"DELETE {filename}")

    def subfolder(self, action, path):
        """Placeholder for subfolder create/delete command."""
        self._sendline(f"SUBFOLDER {action} {path}")

    def upload(self, local_path):
        """Placeholder for upload command."""
        if not os.path.isfile(local_path):
            print("Local file not found.")
            return
        filename = os.path.basename(local_path)
        size = os.path.getsize(local_path)
        self._sendline(f"UPLOAD {filename} {size}")

    def download(self, filename):
        """Placeholder for download command."""
        self._sendline(f"DOWNLOAD {filename}")