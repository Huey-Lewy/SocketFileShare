# main.py
# Entry launcher for CNT3004 Socket File Sharing System.
# Allows user to start the server, start the client, or quit.

import sys          # process exit handling
import os           # filesystem checks and paths
import shutil       # wiping storage and logs
import getpass      # hidden password input
from server import auth, file_ops       # auth bootstrap and storage setup

#### Menu Display ####
MENU = (
    "\n"
    "=== CNT3004 Socket-Based File Sharing System ===\n"
    "Select mode to run:\n"
    "  1. Server\n"
    "  2. Client\n"
    "  3. Quit\n"
    "================================================\n"
)

#### Server data helpers ####
def _server_data_paths():
    """
    Return paths related to server-side data:
    user DB, auth key, storage root, and logs root.
    """
    user_db = auth.USER_DB
    secret_key = auth.SECRET_KEY_FILE
    storage_root = file_ops.STORAGE_ROOT
    logs_root = file_ops.LOGS_ROOT
    return user_db, secret_key, storage_root, logs_root

def _server_data_exists():
    """
    Check if any server data already exists.
    """
    user_db, secret_key, storage_root, logs_root = _server_data_paths()
    paths = [user_db, secret_key, storage_root, logs_root]
    return any(os.path.exists(p) for p in paths)

def _reset_server_data():
    """
    Remove existing server data: users, key, storage, logs.
    """
    user_db, secret_key, storage_root, logs_root = _server_data_paths()
    for path in (user_db, secret_key):
        if os.path.exists(path):
            try:
                os.remove(path)
                print(f"[INFO] Removed file: {path}")
            except OSError as exc:
                print(f"[WARN] Could not remove file {path}: {exc}")

    for path in (storage_root, logs_root):
        if os.path.exists(path):
            try:
                shutil.rmtree(path)
                print(f"[INFO] Removed folder: {path}")
            except OSError as exc:
                print(f"[WARN] Could not remove folder {path}: {exc}")

def _prompt_yes_no(prompt, default=False):
    """
    Simple yes/no prompt.

    Returns:
        bool: True for yes, False for no.
    """
    while True:
        raw = input(prompt).strip().lower()
        if not raw:
            return default
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        print("Please enter 'y' or 'n'.")

def _create_initial_admin():
    """
    Interactively create an initial admin user.

    Returns when a valid admin user has been created.
    """
    print("\n[SETUP] Create initial admin account.")
    while True:
        username = input("Admin username: ").strip()
        if not username:
            print("Username cannot be empty.")
            continue

        pwd1 = getpass.getpass("Admin password: ")
        pwd2 = getpass.getpass("Confirm password: ")
        if pwd1 != pwd2:
            print("Passwords do not match. Try again.\n")
            continue

        try:
            record = auth.register_user(username, pwd1, role=auth.ROLE_ADMIN, overwrite=False)
        except ValueError as exc:
            print(f"Could not create admin: {exc}")
            continue

        # Prepare per-admin storage and log paths.
        file_ops.ensure_user_paths(record["role"], record["user_id"])
        print(f"[INFO] Admin user '{username}' created with id '{record['user_id']}'.\n")
        break

def _bootstrap_server():
    """
    Handle server-side data bootstrap before starting the server.

    Steps:
      - Detect existing auth/storage data.
      - Optionally reset all server data.
      - Ensure at least one admin user exists.
    """
    has_data = _server_data_exists()

    if not has_data:
        print("\n[SETUP] No existing server data found.")
        _create_initial_admin()
        return True

    print("\n[SETUP] Existing server data detected (users, keys, storage, or logs).")
    reset = _prompt_yes_no("Reset server data to default and create a new admin? [y/N]: ", default=False)

    if reset:
        print("[INFO] Resetting server data...")
        _reset_server_data()
        _create_initial_admin()
        return True

    # Keep existing data, but check that at least one admin exists.
    users = auth.list_users()
    admins = [u for u in users if u.get("role") == auth.ROLE_ADMIN]

    if not admins:
        print("\n[SETUP] No admin users found in existing data.")
        _create_initial_admin()

    print("[INFO] Using existing server data.\n")
    return True

#### Main Launcher ####
def main():
    """Main launcher entry point."""
    in_subprogram = False  # Track whether we're inside server/client mode

    try:
        while True:
            try:
                print(MENU, end="")     # Prevent extra newlines
                choice = input("\nEnter choice (1-3): ").strip()

                #### Server Option ####
                if choice == "1":
                    # Bootstrap server data (admin user, storage, logs).
                    if not _bootstrap_server():
                        continue

                    from server.server_main import main as server_main
                    print("\n[INFO] Starting server...\n\n")
                    in_subprogram = True
                    success = server_main()
                    in_subprogram = False
                    if not success:
                        continue        # Return to menu

                #### Client Option ####
                elif choice == "2":
                    from client.client_main import main as client_main
                    print("\n[INFO] Starting client...\n\n")
                    in_subprogram = True
                    success = client_main()
                    in_subprogram = False
                    if not success:
                        continue        # Return to menu

                #### Quit Option ####
                elif choice == "3":
                    print("Exiting program.")
                    break

                #### Invalid Option ####
                else:
                    print("Invalid choice. Please enter 1, 2, or 3.\n")

            #### Inner Ctrl+C or EOF Handling ####
            except (KeyboardInterrupt, EOFError):
                if in_subprogram:
                    print("\n[i] Interrupted. Returning to main menu.\n")
                    in_subprogram = False
                    continue
                else:
                    print("\n[i] Keyboard interrupt detected. Exiting program.\n")
                    sys.exit(0)

    #### Outer Ctrl+C or EOF Handling ####
    except (KeyboardInterrupt, EOFError):
        print("\n[i] Launcher interrupted. Exiting program.\n")
        sys.exit(0)

#### Run as Script ####
if __name__ == "__main__":
    main()
