# main.py
# Entry launcher for CNT3004 Socket File Sharing System.
# Allows user to start the server, start the client, or quit.

import sys

def show_menu():
    """Display the startup menu."""
    print("=== CNT3004 Socket-Based File Sharing System ===")
    print("Select mode to run:")
    print("  1. Server")
    print("  2. Client")
    print("  3. Quit")
    print("================================================")

def main():
    """Main launcher entry point."""
    while True:
        show_menu()
        choice = input("Enter choice (1-3): ").strip()

        if choice == "1":
            from server.server_main import main as server_main
            print("\n[INFO] Starting server...\n")
            server_main()
            # Return to menu after server_main() exits

        elif choice == "2":
            from client.client_main import main as client_main
            print("\n[INFO] Starting client...\n")
            success = client_main()
            if not success:
                # Connection failed — return to menu
                continue
            else:
                # Client session finished normally — return to menu
                continue

        elif choice == "3":
            print("Exiting program.")
            sys.exit(0)

        else:
            print("Invalid choice. Please enter 1, 2, or 3.\n")

if __name__ == "__main__":
    main()