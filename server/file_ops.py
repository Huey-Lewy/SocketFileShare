# server/file_ops.py
# Handles file operations for upload, download, delete, directory listing, and subfolder management.

import os       # storage paths and filesystem work
from analysis.performance_eval import timed     # timing for file operations

#### Paths and constants ####
ENC = "utf-8"
BASE_DIR = os.path.dirname(__file__)

# Root directory for all file data managed by the server.
# This is treated as the "root" of the folder system.
STORAGE_ROOT = os.path.join(BASE_DIR, "storage")

# Suggested chunk size for streaming large files (upload/download).
CHUNK_SIZE = 64 * 1024  # 64 KB

#### Path helpers ####
def _make_dirs(path):
    """
    Create a directory tree if it does not exist.

    This is used both for the global storage root and for per-user folders.
    """
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)

def init_storage_root():
    """
    Initialize that the global storage root exists.

    main.py or server_main.py should call this during server bootstrap.
    """
    _make_dirs(STORAGE_ROOT)

def get_user_storage_dir(user_id, username):
    """
    Compute the absolute path for a user's storage directory.

    Layout:
        server/storage/ID_<user_id>_<username>/

    Parameters:
        user_id  (str): Numeric ID from auth (e.g., "0001", "0002").
        username (str): Associated username (e.g., "helloworld").

    Returns:
        str: Absolute path to that user's storage directory (not created).
    """
    init_storage_root()

    # Fallbacks in case something is missing; helps avoid crashing.
    if not user_id:
        user_id = "UNKNOWN"
    if not username:
        username = "unknown"

    folder_name = f"ID_{user_id}_{username}"
    # NOTE: If usernames may contain path-unsafe chars, a sanitization step can be added here.
    return os.path.abspath(os.path.join(STORAGE_ROOT, folder_name))

def init_user_storage_dir(user_id, username):
    """
    Initialize a user's storage directory exists and return its path.

    Parameters:
        user_id  (str): Numeric ID from auth (e.g., "0001").
        username (str): Associated username.

    Returns:
        str: Absolute path to the existing per-user storage directory.
    """
    user_dir = get_user_storage_dir(user_id, username)
    _make_dirs(user_dir)
    return user_dir

def resolve_path(session, rel_path):
    """
    Map a client-provided relative path to an absolute path inside
    the session's storage_root. Reject attempts to leave that root.

    Parameters:
        session: Object with a 'storage_root' attribute (e.g., ClientSession).
        rel_path (str): Relative path sent by the client (e.g., "file.txt", "subdir/file.bin").

    Returns:
        str: Absolute path under session.storage_root.

    Raises:
        ValueError: If the resolved path is outside the storage root, or invalid.
    """
    # Initialize storage_root is absolute to avoid surprises.
    base = os.path.abspath(session.storage_root)
    target = os.path.abspath(os.path.join(base, rel_path))

    try:
        common = os.path.commonpath([base, target])
    except ValueError:
        # Occurs if paths are on different drives or malformed
        raise ValueError("Invalid path")

    if common != base:
        # Prevent directory traversal outside the user's folder
        raise ValueError("Path outside storage root")

    return target

def _send_line(conn, text):
    """
    Send a single line to the client, appending '\n'.

    Parameters:
        conn: Socket-like object (has sendall()).
        text (str): Response line to send.
    """
    data = (text.rstrip("\n") + "\n").encode(ENC)
    conn.sendall(data)

#### Command handlers ####
def handle_upload(session, line, perf):
    """
    Handle file upload request from a client.

    Protocol (proposed):
        UPLOAD <remote_path> <size_bytes>

    Where:
        remote_path: Path relative to the user's storage root.
        size_bytes:  Decimal size of the file in bytes.

    The actual file data transfer will be implemented by teammates.
    """
    timer = timed()  # measure upload handling time
    received_bytes = 0

    try:
        # Enforce that only authenticated clients can upload files.
        if not getattr(session, "authenticated", False):
            _send_line(session.conn, "ERR UPLOAD Not authenticated")
            print("[UPLOAD] denied: client not authenticated")
            return

        parts = line.split()
        if len(parts) < 3:
            _send_line(session.conn, "ERR UPLOAD Usage: UPLOAD <remote_path> <size_bytes>")
            print("[UPLOAD] failed: bad syntax")
            return

        # Expected format: UPLOAD <remote_path> <size_bytes>
        _, rel_path, size_str = parts[0], parts[1], parts[2]

        # Validate and parse the size field.
        try:
            file_size = int(size_str)
            if file_size < 0:
                raise ValueError
        except ValueError:
            _send_line(session.conn, "ERR UPLOAD Invalid size")
            print("[UPLOAD] failed: invalid size")
            return

        # Translate client path to a safe absolute path inside the user's folder.
        try:
            target_path = resolve_path(session, rel_path)
        except ValueError:
            _send_line(session.conn, "ERR UPLOAD Invalid path")
            print(f"[UPLOAD] failed: invalid path '{rel_path}'")
            return

        # Create parent directories if needed.
        parent_dir = os.path.dirname(target_path)
        _make_dirs(parent_dir)

        print(f"[UPLOAD] Starting: {rel_path} ({file_size} bytes) -> {target_path}")

        # Send READY so client can start streaming bytes.
        _send_line(session.conn, "READY")

        try:
            with open(target_path, "wb") as f:
                # Receive exactly file_size bytes from the client.
                while received_bytes < file_size:
                    remaining = file_size - received_bytes
                    to_read = min(CHUNK_SIZE, remaining)
                    chunk = session.conn.recv(to_read)
                    if not chunk:
                        raise ConnectionResetError("Connection lost during transfer")
                    f.write(chunk)
                    received_bytes += len(chunk)

            _send_line(session.conn, f"OK UPLOAD {rel_path}")
            print(f"[UPLOAD] Finished. {rel_path} uploaded by {session.username}")
        except OSError as e:
            print(f"[UPLOAD] File IO error: {e}")
            _send_line(session.conn, f"ERR UPLOAD Server disk error: {e}")
        except Exception as e:
            print(f"[UPLOAD] Transfer error: {e}")
            _send_line(session.conn, "ERR UPLOAD Transfer interrupted")

    except Exception as e:
        print(f"[UPLOAD] Critical error: {e}")
        _send_line(session.conn, "ERR UPLOAD Internal error")

    finally:
        elapsed = timer()
        perf.record_transfer(operation="upload", bytes_count=received_bytes, seconds=elapsed, source="server")

def handle_download(session, line, perf):
    """
    Handle file download request from a client.

    Protocol (proposed):
        DOWNLOAD <remote_path>

    Where:
        remote_path: Path relative to the user's storage root.

    The actual file streaming logic will be implemented by teammates.
    """
    timer = timed()  # measure download handling time
    sent_bytes = 0

    try:
        # Enforce that only authenticated clients can download files.
        if not getattr(session, "authenticated", False):
            _send_line(session.conn, "ERR DOWNLOAD Not authenticated")
            print("[DOWNLOAD] denied: client not authenticated")
            return

        parts = line.split()
        if len(parts) != 2:
            _send_line(session.conn, "ERR DOWNLOAD Usage: DOWNLOAD <remote_path>")
            print("[DOWNLOAD] failed: bad syntax")
            return

        _, rel_path = parts[0], parts[1]

        # Map the remote path to the actual file in the user's storage directory.
        try:
            target_path = resolve_path(session, rel_path)
        except ValueError:
            _send_line(session.conn, "ERR DOWNLOAD Invalid path")
            print(f"[DOWNLOAD] failed: invalid path '{rel_path}'")
            return

        if not os.path.isfile(target_path):
            _send_line(session.conn, "ERR DOWNLOAD File not found")
            print(f"[DOWNLOAD] failed: file not found at {target_path}")
            return

        file_size = os.path.getsize(target_path)

        print(f"[DOWNLOAD] Preparing to send: {rel_path} ({file_size} bytes)...")

        # Send size header: "SIZE <file_size>"
        _send_line(session.conn, f"SIZE {file_size}")

        # Wait for client READY
        try:
            resp = session.conn.recv(1024).decode(ENC).strip()
            if resp != "READY":
                print(f"[DOWNLOAD] Client rejected transfer or sent unexpected response: {resp}")
                return
        except Exception:
            print("[DOWNLOAD] Client disconnected or failed READY response.")
            return

        try:
            with open(target_path, "rb") as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    session.conn.sendall(chunk)
                    sent_bytes += len(chunk)

            if sent_bytes == file_size:
                print(f"[DOWNLOAD] Success: {sent_bytes} bytes sent for '{rel_path}'")
            else:
                print(f"[DOWNLOAD] Size mismatch. Expected {file_size}, sent {sent_bytes}.")
        except Exception as e:
            print(f"[DOWNLOAD] Error: {e}")

    finally:
        elapsed = timer()
        perf.record_transfer(operation="download", bytes_count=sent_bytes, seconds=elapsed, source="server")

def handle_delete(session, line, perf):
    """
    Handle delete request from a client.

    Protocol (proposed):
        DELETE <remote_path>

    Where:
        remote_path: Path relative to the user's storage root.
    """
    timer = timed()  # measure delete handling time

    try:
        # Enforce that only authenticated clients can delete files.
        if not getattr(session, "authenticated", False):
            _send_line(session.conn, "ERR DELETE Not authenticated")
            print("[DELETE] denied: client not authenticated")
            return

        parts = line.split()
        if len(parts) != 2:
            _send_line(session.conn, "ERR DELETE Usage: DELETE <remote_path>")
            print("[DELETE] failed: bad syntax")
            return

        _, rel_path = parts[0], parts[1]

        # Resolve the path within the user's storage.
        try:
            target_path = resolve_path(session, rel_path)
        except ValueError:
            _send_line(session.conn, "ERR DELETE Invalid path")
            print(f"[DELETE] failed: invalid path '{rel_path}'")
            return

        print(f"[DELETE] stub: {rel_path} -> {target_path}")

        # Placeholder: check if target_path is in use by another transfer; send error if busy.
        # Placeholder: check if file exists; send error if missing.
        # Placeholder: remove the file from disk.
        # Placeholder: send success or error response to client.
        # Placeholder: record delete status in any higher-level reporting if desired.

        _send_line(session.conn, "ERR DELETE Not implemented")

    finally:
        elapsed = timer()
        perf.record_response(operation="delete", seconds=elapsed, source="server")

def handle_dir(session, line, perf):
    """
    Handle directory listing request from a client.

    Protocol (proposed):
        DIR
        DIR <subpath>

    Where:
        subpath: Optional relative subdirectory under the user's storage root.
    """
    timer = timed()  # measure dir handling time

    try:
        # Enforce that only authenticated clients can view directory listings.
        if not getattr(session, "authenticated", False):
            _send_line(session.conn, "ERR DIR Not authenticated")
            print("[DIR] denied: client not authenticated")
            return

        parts = line.split(maxsplit=1)
        rel_path = "."
        if len(parts) == 2:
            rel_path = parts[1].strip()

        # Resolve target directory inside user's storage root.
        try:
            target_path = resolve_path(session, rel_path)
        except ValueError:
            _send_line(session.conn, "ERR DIR Invalid path")
            print(f"[DIR] failed: invalid path '{rel_path}'")
            return

        print(f"[DIR] stub: listing for {target_path}")

        # Placeholder: read entries under target_path (files and subfolders).
        # Placeholder: format entries as a simple list (one item per line).
        # Placeholder: send listing to client, possibly with a BEGIN/END marker.
        # Placeholder: record directory listing status in any higher-level reporting.

        _send_line(session.conn, "ERR DIR Not implemented")

    finally:
        elapsed = timer()
        perf.record_response(operation="dir", seconds=elapsed, source="server")

def handle_subfolder(session, line, perf):
    """
    Handle subfolder management request (create/delete).

    Protocol (proposed):
        SUBFOLDER create <path>
        SUBFOLDER delete <path>

    Where:
        path: Relative folder path under the user's storage root.
    """
    timer = timed()  # measure subfolder handling time

    try:
        # Enforce that only authenticated clients can manage subfolders.
        if not getattr(session, "authenticated", False):
            _send_line(session.conn, "ERR SUBFOLDER Not authenticated")
            print("[SUBFOLDER] denied: client not authenticated")
            return

        parts = line.split(maxsplit=2)
        if len(parts) < 3:
            _send_line(session.conn, "ERR SUBFOLDER Usage: SUBFOLDER {create|delete} <path>")
            print("[SUBFOLDER] failed: bad syntax")
            return

        _, action, rel_path = parts[0], parts[1].lower(), parts[2].strip()

        if action not in ("create", "delete"):
            _send_line(session.conn, "ERR SUBFOLDER Action must be 'create' or 'delete'")
            print(f"[SUBFOLDER] failed: invalid action '{action}'")
            return

        # Resolve target directory inside user's storage root.
        try:
            target_path = resolve_path(session, rel_path)
        except ValueError:
            _send_line(session.conn, "ERR SUBFOLDER Invalid path")
            print(f"[SUBFOLDER] failed: invalid path '{rel_path}'")
            return

        print(f"[SUBFOLDER] stub: {action} {rel_path} -> {target_path}")

        # create directory tree at target_path when action is 'create'.
        if action == "create":
            if os.path.exists(target_path):
                if os.path.isdir(target_path):
                    #Directory Already Exists
                    _send_line(session.conn, "ERR SUBFOLDER Directory already exists")
                    print(f"[SUBFOLDER] create failed: directory already exists {target_path}")
                else:
                    # A file with the same name as the folder exists at that path
                    _send_line(session.conn, "ERR SUBFOLDER A file with the same name exists at that path")
                    print(f"[SUBFOLDER] create failed: file exists at {target_path}")
                return

            try:
                os.makedirs(target_path, exist_ok=True)
                #make the directory
            except OSError as exc:
                #Handling any problems while creating file
                _send_line(session.conn, "ERR SUBFOLDER Failed to create directory")
                print(f"[SUBFOLDER] create failed: OSERROR")
                return
            #send response to client
            _send_line(session.conn, "SUBFOLDER Directory created!")
            print(f"[SUBFOLDER] created '{target_path}'")
            return

        # Placeholder: delete directory at target_path when action is 'delete', with safety checks.
        elif action == "delete":
            if not os.path.exists(target_path):
                # if path does not exist
                _send_line(session.conn, "ERR SUBFOLDER Directory does not exist")
                print(f"[SUBFOLDER] delete failed: directory does not exist {target_path}")
                return

            if not os.path.isdir(target_path):
                # if it is not a directory
                _send_line(session.conn, "ERR SUBFOLDER Target is not directory")
                print(f"[SUBFOLDER] delete failed: target is not a directory {target_path}")
                return

            try:
                #Check if directory has contents inside it(more directories or files)
                if os.listdir(target_path):
                    _send_line(session.conn, "ERR SUBFOLDER Directory is not empty")
                    print(f"[SUBFOLDER] delete failed: directory is not empty {target_path}")
                    return
            except OSError as e:
                _send_line(session.conn, "ERR SUBFOLDER Cannot inspect directory")
                print(f"[SUBFOLDER] delete failed: OS ERROR {e}")
                return

            try:
                #actually remove the directory
                os.rmdir(target_path)
            except OSError as e:
                _send_line(session.conn, "ERR SUBFOLDER Failed to delete directory")
                print(f"[SUBFOLDER] delete failed while removing directory: {e}")
                return
                #send response to client
            _send_line(session.conn, "SUBFOLDER Directory deleted!")
            print(f"[SUBFOLDER] deleted {target_path}")
            return

        # Placeholder: record subfolder operation status in any higher-level reporting.

    finally:
        elapsed = timer()
        perf.record_response(operation="subfolder", seconds=elapsed, source="server")
