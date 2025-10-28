import socket
import threading
import struct
import os
import time
import io
import zipfile
import shutil
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox, simpledialog
import platform

# =========================
# CONFIG
# =========================
PORT = 5000
DISCOVERY_PORT = 5001
BROADCAST_INTERVAL = 2
SHARED_DIR = "shared"
os.makedirs(SHARED_DIR, exist_ok=True)

# =========================
# Shared Helpers
# =========================
def send_packet(sock, data: bytes):
    """Send a length-prefixed packet safely."""
    try:
        sock.sendall(struct.pack("!I", len(data)) + data)
    except Exception:
        pass

def recv_packet(sock):
    """Receive a length-prefixed packet safely."""
    try:
        header = sock.recv(4)
        if not header:
            return None
        msg_len = struct.unpack("!I", header)[0]
        data = b""
        while len(data) < msg_len:
            packet = sock.recv(msg_len - len(data))
            if not packet:
                return None
            data += packet
        return data
    except Exception:
        return None

# =========================
# Server Logic
# =========================
clients = {}
gui_logger = None  # set by GUI

def log_to_gui(message: str):
    global gui_logger
    try:
        if gui_logger:
            gui_logger(message)
        else:
            print(message)
    except tk.TclError:
        print(message)

def broadcast(sender_conn, message: str):
    for conn in list(clients.keys()):
        if conn != sender_conn:
            try:
                send_packet(conn, message.encode())
            except:
                conn.close()
                clients.pop(conn, None)

def handle_client(conn, addr):
    try:
        name = recv_packet(conn).decode()
        clients[conn] = name
        log_to_gui(f"{name} joined from {addr[0]}")
        broadcast(conn, f"SERVER> {name} joined the chat.")
        while True:
            data = recv_packet(conn)
            if not data:
                break

            if data.startswith(b"UPLOAD:"):
                _, filename = data.split(b":", 1)
                filename = filename.decode()
                file_data = recv_packet(conn)
                path = os.path.join(SHARED_DIR, filename)
                with open(path, "wb") as f:
                    f.write(file_data)
                send_packet(conn, f"SERVER> File '{filename}' uploaded.".encode())
                log_to_gui(f"Received file from {name}: {filename}")
                continue

            if data.startswith(b"PULL:"):
                _, filename = data.split(b":", 1)
                filename = filename.decode()
                path = os.path.join(SHARED_DIR, filename)
                if os.path.exists(path):
                    with open(path, "rb") as f:
                        file_data = f.read()
                    send_packet(conn, f"FILE:{filename}".encode())
                    send_packet(conn, file_data)
                    log_to_gui(f"Sent '{filename}' to {name}")
                else:
                    send_packet(conn, f"SERVER> File '{filename}' not found.".encode())
                continue

            if data.startswith(b"LISTFILES"):
                files = os.listdir(SHARED_DIR)
                file_list = "\n".join(files) if files else "(no shared files yet)"
                send_packet(conn, f"SERVER> Shared files:\n{file_list}".encode())
                continue

            if data.startswith(b"RMV:"):
                _, target = data.split(b":", 1)
                target = target.decode().strip()
                target_path = os.path.join(SHARED_DIR, target)
                if os.path.exists(target_path):
                    try:
                        if os.path.isdir(target_path):
                            shutil.rmtree(target_path)
                            send_packet(conn, f"SERVER> Directory '{target}' removed.".encode())
                        else:
                            os.remove(target_path)
                            send_packet(conn, f"SERVER> File '{target}' removed.".encode())
                        log_to_gui(f"{name} removed '{target}'")
                    except Exception as e:
                        send_packet(conn, f"SERVER> Error removing '{target}': {e}".encode())
                else:
                    send_packet(conn, f"SERVER> '{target}' not found.".encode())
                continue

            msg = data.decode(errors="ignore")
            broadcast(conn, f"{name}> {msg}")
            log_to_gui(f"{name}> {msg}")

    except Exception as e:
        log_to_gui(f"Error with {addr}: {e}")
    finally:
        cname = clients.pop(conn, "Unknown")
        conn.close()
        broadcast(None, f"SERVER> {cname} disconnected.")
        log_to_gui(f"{cname} disconnected")

def accept_clients(server):
    while True:
        try:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except Exception:
            break

def broadcast_host_info(ip):
    """Send UDP broadcasts advertising this host."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    name = os.getenv("COMPUTERNAME") or os.getenv("HOSTNAME") or platform.node()
    while True:
        msg = f"HOST:{name}:{ip}".encode()
        try:
            sock.sendto(msg, ("255.255.255.255", DISCOVERY_PORT))
        except Exception:
            pass
        time.sleep(BROADCAST_INTERVAL)

def start_server():
    host_ip = get_local_ip()
    log_to_gui(f"Hosting on {host_ip}:{PORT}")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host_ip, PORT))
    server.listen()
    threading.Thread(target=lambda: accept_clients(server), daemon=True).start()
    threading.Thread(target=lambda: broadcast_host_info(host_ip), daemon=True).start()
    return host_ip

# =========================
# Discovery
# =========================
def discover_hosts(timeout=3):
    """Find available LAN hosts."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        sock.bind(("", DISCOVERY_PORT))
    except Exception:
        pass  # macOS sometimes forbids re-binding broadcast ports
    sock.settimeout(timeout)
    found = {}
    start = time.time()
    while time.time() - start < timeout:
        try:
            data, addr = sock.recvfrom(1024)
            msg = data.decode()
            if msg.startswith("HOST:"):
                _, name, ip = msg.split(":")
                found[ip] = name
        except socket.timeout:
            break
        except Exception:
            continue
    sock.close()
    return found

# =========================
# GUI Client
# =========================
class ChatApp(tk.Tk):
    def __init__(self):
        super().__init__()
        global gui_logger
        gui_logger = self.log
        self.title("OpenDrop")
        self.geometry("780x580")
        self.sock = None
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.create_menu()

    # ---------- LOG ----------
    def log(self, text):
        """Thread-safe GUI logging."""
        self.after(0, self._safe_log, text)

    def _safe_log(self, text):
        if not hasattr(self, "chat") or not self.chat.winfo_exists():
            return
        self.chat.config(state="normal")
        self.chat.insert("end", text + "\n")
        self.chat.config(state="disabled")
        self.chat.yview("end")

    # ---------- MENU ----------
    def create_menu(self):
        frame = tk.Frame(self)
        frame.pack(expand=True)
        tk.Label(frame, text="LAN Chat + File Share", font=("Arial", 18, "bold")).pack(pady=20)
        tk.Button(frame, text="Host Server", width=25, command=self.host_mode).pack(pady=10)
        tk.Button(frame, text="Join Server", width=25, command=self.join_mode).pack(pady=10)
        self.chat = scrolledtext.ScrolledText(self, state="disabled", wrap="word", height=15)
        self.chat.pack(fill="both", expand=True, padx=10, pady=10)

    # ---------- HOST/JOIN ----------
    def host_mode(self):
        ip = start_server()
        self.log(f"Hosting server on {ip}...")
        self.after(1000, lambda: self.launch_client(ip))

    def join_mode(self):
        hosts = discover_hosts()
        if not hosts:
            messagebox.showinfo("No Hosts Found", "No LAN hosts detected.")
            return
        win = tk.Toplevel(self)
        win.title("Select Host")
        win.geometry("400x300")
        tk.Label(win, text="Discovered Hosts").pack(pady=5)
        box = tk.Listbox(win)
        box.pack(fill="both", expand=True, padx=10, pady=10)
        for ip, name in hosts.items():
            box.insert(tk.END, f"{name} ({ip})")
        tk.Button(win, text="Connect", command=lambda: self._connect(box, hosts, win)).pack(pady=5)

    def _connect(self, box, hosts, win):
        sel = box.curselection()
        if not sel:
            messagebox.showwarning("Select", "Please choose a host.")
            return
        ip = list(hosts.keys())[sel[0]]
        win.destroy()
        self.launch_client(ip)

    # ---------- CHAT WINDOW ----------
    def launch_client(self, host_ip):
        for w in self.winfo_children():
            w.destroy()
        name = simpledialog.askstring("Name", "Enter your name:")
        if not name:
            return
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host_ip, PORT))
        send_packet(self.sock, name.encode())

        self.chat = scrolledtext.ScrolledText(self, state="disabled", wrap="word")
        self.chat.pack(fill="both", expand=True, padx=10, pady=10)

        entry_frame = tk.Frame(self)
        entry_frame.pack(fill="x", padx=10, pady=5)
        self.entry = tk.Entry(entry_frame)
        self.entry.pack(side="left", fill="x", expand=True)
        tk.Button(entry_frame, text="Send", command=self.send_msg).pack(side="right")

        btn_frame = tk.Frame(self)
        btn_frame.pack(fill="x", pady=5)
        tk.Button(btn_frame, text="Push File", command=self.push_file).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Push Folder", command=self.push_folder).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Pull File", command=self.pull_file).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Pull Folder", command=self.pull_folder).pack(side="left", padx=5)
        tk.Button(btn_frame, text="List Files", command=lambda: send_packet(self.sock, b"LISTFILES")).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Remove", command=self.remove_item).pack(side="left", padx=5)

        threading.Thread(target=self.listen, daemon=True).start()

    # ---------- SOCKET HANDLER ----------
    def listen(self):
        while True:
            try:
                data = recv_packet(self.sock)
                if not data:
                    break
                if data.startswith(b"FILE:"):
                    filename = data.decode().split(":", 1)[1]
                    file_data = recv_packet(self.sock)
                    save_path = f"received_{filename}"
                    with open(save_path, "wb") as f:
                        f.write(file_data)
                    if filename.endswith(".zip"):
                        extract_dir = save_path[:-4]
                        os.makedirs(extract_dir, exist_ok=True)
                        with zipfile.ZipFile(save_path, "r") as z:
                            z.extractall(extract_dir)
                        self.log(f"Extracted folder: {extract_dir}")
                    else:
                        self.log(f"Received file: {save_path}")
                else:
                    self.log(data.decode(errors="ignore"))
            except Exception:
                break

    # ---------- FILE OPS ----------
    def send_msg(self):
        msg = self.entry.get().strip()
        if msg:
            send_packet(self.sock, msg.encode())
            self.entry.delete(0, tk.END)

    def push_file(self):
        path = filedialog.askopenfilename()
        if not path:
            return
        send_packet(self.sock, f"UPLOAD:{os.path.basename(path)}".encode())
        with open(path, "rb") as f:
            send_packet(self.sock, f.read())
        self.log(f"Sent file: {os.path.basename(path)}")

    def push_folder(self):
        folder = filedialog.askdirectory()
        if not folder:
            return
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(folder):
                for file in files:
                    full = os.path.join(root, file)
                    zipf.write(full, os.path.relpath(full, folder))
        data = buf.getvalue()
        zipname = f"{os.path.basename(folder)}.zip"
        send_packet(self.sock, f"UPLOAD:{zipname}".encode())
        send_packet(self.sock, data)
        self.log(f"Sent folder: {zipname}")

    def pull_file(self):
        name = simpledialog.askstring("Pull File", "Enter filename:")
        if name:
            send_packet(self.sock, f"PULL:{name}".encode())

    def pull_folder(self):
        name = simpledialog.askstring("Pull Folder", "Enter folder name:")
        if name:
            send_packet(self.sock, f"PULL:{name}.zip".encode())

    def remove_item(self):
        name = simpledialog.askstring("Remove", "Enter file/folder name to delete:")
        if name:
            send_packet(self.sock, f"RMV:{name}".encode())

    # ---------- EXIT ----------
    def on_close(self):
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
        self.destroy()

# =========================
# Utility
# =========================
def get_local_ip():
    """Return local LAN IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    s.close()
    return ip

# =========================
# Entry Point
# =========================
if __name__ == "__main__":
    ChatApp().mainloop()
