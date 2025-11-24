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
    Send a single line to the client, appending '\\n'.

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
    ##creates variable for received bytes
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

        size_str = parts [1]
        rel_path = "".join(parts[1:-1])

        # Validate and parse the size field.
        try:
            ##names it file_size for more clarity.
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

        # At this point, we have:
        #   - target_path: where the file should be stored
        #   - size: total expected bytes to receive
        print(f"[UPLOAD] Starting: {rel_path} ({file_size} bytes) -> {target_path}")

        ##send ACK as "ready"
        _send_line(session.conn, "READY")


        try:
            with open (target_path, "wb") as f:
                ## go as long as the received is less than the actual file
                while received_bytes < file_size:

                    remaining = file_size - received_bytes

                    to_read = min (CHUNK_SIZE, remaining)

                    chunk = session.conn.recv(to_read)

                    if not chunk:
                        raise ConnectionResetError ("Connection terminated. Reason: Connection lost during transfer.")
                    f.write (chunk)
                    received_bytes += len(chunk)

            _send_line(session.conn, f"OK UPLOAD {rel_path}")
            print (f"[UPLOAD] Finished. {rel_path} uploaded by {session.username}")
        except OSError as e:
            print (f"[UPLOAD] File IO Error: {e}")
            _send_line(session.conn, f"ERR UPLOAD Server Disk Error: {e}")
        except Exception as e:
            print (f"[UPLOAD] Transfer Error: {e}")
            _send_line(session.conn, "ERR UPLOAD Transfer Interrupted")

    except Exception as e:
        print (f"[UPLOAD] Critical Error: {e}")

        '''
        # Placeholder: check if target_path already exists and ask client about overwrite.
        # Placeholder: receive exactly <size> bytes from session.conn in CHUNK_SIZE chunks.
        # Placeholder: write received bytes to target_path.
        # Placeholder: send success or error response after write completes.
        # Placeholder: record upload status in any higher-level reporting if desired.
        '''
        _send_line(session.conn, "ERR UPLOAD Not implemented")

    finally:
        elapsed = timer()
        # Placeholder: replace bytes_count=0 with the actual number of bytes written.
        perf.record_transfer(operation="upload", bytes_count=0, seconds=elapsed, source="server")

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

        print(f"[DOWNLOAD] stub: {rel_path} -> {target_path}")

        # Placeholder: check if target_path exists.
        # Placeholder: send error response if file does not exist.
        # Placeholder: send file size first.
        # Placeholder: stream file contents from disk to client in CHUNK_SIZE chunks.
        # Placeholder: handle broken connections and partial sends.
        # Placeholder: record download status in any higher-level reporting if desired.

        _send_line(session.conn, "ERR DOWNLOAD Not implemented")

    finally:
        elapsed = timer()
        # Placeholder: replace bytes_count=0 with the actual number of bytes sent.
        perf.record_transfer(operation="download", bytes_count=0, seconds=elapsed, source="server")

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

        # Placeholder: create directory tree at target_path when action is 'create'.
        # Placeholder: delete directory at target_path when action is 'delete', with safety checks.
        # Placeholder: send success or error response to client.
        # Placeholder: record subfolder operation status in any higher-level reporting.

        _send_line(session.conn, "ERR SUBFOLDER Not implemented")

    finally:
        elapsed = timer()
        perf.record_response(operation="subfolder", seconds=elapsed, source="server")
