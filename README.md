# SocketFileShare
**Description**: Socket-based distributed file sharing system for Computer Networks.

**Project Stucture**:
```
SocketFileShare/
│
├── README.md                 # Project overview, setup, and usage
├── requirements.txt          # Python dependencies
│
├── server/                   # Server-side modules
│   ├── server_main.py        # Starts the multithreaded server
│   ├── auth.py               # Handles login, encryption, and verification
│   └── file_ops.py           # File management: upload, download, dir, etc.
│
├── client/                   # Client-side modules
│   ├── client_main.py        # Runs client connection and session
│   └── commands.py           # Processes user input and client commands
│
└── analysis/                 # Network performance metrics
     └── performance_eval.py  # Collects data rates, transfer times, response times
```