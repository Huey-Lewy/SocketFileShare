# main.py
# Entry launcher for CNT3004 Socket File Sharing System.
# Allows user to start the server, start the client, or quit.

import sys

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
