# server/server_main.py
# Starts the multithreaded server application.

import socket
import threading
import sys
import os
from analysis.performance_eval import PerfRecorder, timed   # For timing and metric tracking
from server import file_ops     # For file operation handling (upload, download, etc.)
from server import auth         # For authentication handling

#### Constants ####
BUFFER = 64 * 1024  # 64KB buffer size for file transfer
ENC = 'utf-8'       # Encoding format for strings
BACKLOG = 5         # Max queued connections

#### Initialize performance recorder (shared globally across client threads) ####
perf = PerfRecorder()

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

#### Client Handler ####
def handle_client(conn, addr):
    """
    Handle communication with a connected client.

    Placeholder: authentication, command parsing, and file operations
    (upload, download, delete, dir, subfolder) will be implemented here.
    """
    print(f"[+] New connection from {addr}")
    timer = timed()  # Measure total session duration

    try:
        # Placeholder: Add authentication handshake here
        conn.sendall("OK@Connected to server\n".encode(ENC))
        # Placeholder: record authentication latency when implemented

        while True:
            data = conn.recv(BUFFER)
            if not data:
                break
            decoded = data.decode(ENC).strip()
            print(f"[{addr}] {decoded}")

            # Placeholder: Add command parsing and dispatch to file_ops/auth modules here
            if decoded.upper() == "LOGOUT":
                conn.sendall("OK@Logout successful\n".encode(ENC))
                break
            else:
                conn.sendall(f"OK@Received: {decoded}\n".encode(ENC))

    except ConnectionResetError:
        print(f"[x] Connection reset by {addr}")

    except Exception as e:
        print(f"[x] Error with {addr}: {e}")

    finally:
        conn.close()
        elapsed = timer()
        perf.record_response(operation="session", seconds=elapsed)
        print(f"[-] Disconnected from {addr} (Session Duration: {elapsed:.2f}s)")
        # Placeholder: record per-client session duration for performance summary.

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

    # Placeholder: record server startup timestamp
    start_timer = timed()

    try:
        while True:
            try:
                conn, addr = server_sock.accept()
                # Placeholder: record per-client connection start
                thread = threading.Thread(
                    target=handle_client, args=(conn, addr), daemon=True
                )
                thread.start()
                # Placeholder: could increment active session counter here

            except socket.timeout:
                # Allows loop to stay responsive to interrupts
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
        # Placeholder: dump and log performance metrics for analysis.

    # Return False so main.py menu reloads
    return False

#### Run as Script ####
if __name__ == "__main__":
    main()
