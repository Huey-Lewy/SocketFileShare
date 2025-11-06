# SocketFileShare
**Description**: Socket-based distributed file sharing system for CNT3004 Computer Networks. Uses Python sockets to implement file operations, client-server communication, and performance evaluation.

### **Quick Start**: (Placeholder)
1. **Run** the launcher: `python main.py`
2. **Select** Server or Client mode.
3. **Follow** on-screen prompts to configure IP, port, and commands.

### **Features**: (Placeholder)
- (Placeholder)
- (Placeholder)
- (Placeholder)
- (Placeholder)
- (Placeholder)

### **Project Stucture**:
```
SocketFileShare/
│
├── analysis/                 # Performance metrics
│   └── performance_eval.py   # Collects transfer times, data rates, response times
│
├── client/                   # Client-side modules
│   ├── client_main.py        # Runs client connection and session
│   └── commands.py           # Processes user input and client commands
│
├── server/                   # Server-side modules
│   ├── auth.py               # Handles login and authentication logic
│   ├── file_ops.py           # File operations (upload, download, dir, etc.)
│   └── server_main.py        # Starts multithreaded server
│
├── .gitignore                # Git ignore rules for project files
├── main.py                   # Unified launcher for server/client selection
├── README.md                 # Project overview, setup, and usage
└── requirements.txt          # Python dependencies
```
