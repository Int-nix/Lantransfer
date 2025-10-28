import socket
import threading
import struct
import os
import time
import zipfile
import io
import shutil

PORT = 5000
DISCOVERY_PORT = 5001
BROADCAST_INTERVAL = 2
clients = {}
SHARED_DIR = "shared"
os.makedirs(SHARED_DIR, exist_ok=True)

# =========================
# Shared helpers
# =========================
def send_packet(sock, data: bytes):
    """Send a length-prefixed packet."""
    sock.sendall(struct.pack("!I", len(data)) + data)

def recv_packet(sock):
    """Receive a length-prefixed packet."""
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

# =========================
# Server side
# =========================
def broadcast(sender_conn, message: str):
    """Send message to all clients except sender."""
    for conn in list(clients.keys()):
        if conn != sender_conn:
            try:
                send_packet(conn, message.encode())
            except:
                conn.close()
                clients.pop(conn, None)

def handle_client(conn, addr):
    """Handle a connected client."""
    try:
        name = recv_packet(conn).decode()
        clients[conn] = name
        print(f"[+] {name} joined from {addr[0]}")
        broadcast(conn, f"SERVER> {name} joined the chat.")

        while True:
            data = recv_packet(conn)
            if not data:
                break

            # --- Upload file or folder ---
            if data.startswith(b"UPLOAD:"):
                _, filename = data.split(b":", 1)
                filename = filename.decode()
                file_data = recv_packet(conn)
                path = os.path.join(SHARED_DIR, filename)
                with open(path, "wb") as f:
                    f.write(file_data)
                send_packet(conn, f"SERVER> File '{filename}' uploaded.".encode())

            # --- Pull file or folder ---
            elif data.startswith(b"PULL:"):
                _, filename = data.split(b":", 1)
                filename = filename.decode()
                path = os.path.join(SHARED_DIR, filename)
                if os.path.exists(path):
                    with open(path, "rb") as f:
                        file_data = f.read()
                    send_packet(conn, f"FILE:{filename}".encode())
                    send_packet(conn, file_data)
                else:
                    send_packet(conn, f"SERVER> File '{filename}' not found.".encode())

            # --- List files in shared dir ---
            elif data.startswith(b"LISTFILES"):
                files = os.listdir(SHARED_DIR)
                file_list = "\n".join(files) if files else "(no shared files yet)"
                send_packet(conn, f"SERVER> Shared files:\n{file_list}".encode())

            # --- Remove file or directory ---
            elif data.startswith(b"RMV:"):
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
                    except Exception as e:
                        send_packet(conn, f"SERVER> Error removing '{target}': {e}".encode())
                else:
                    send_packet(conn, f"SERVER> '{target}' not found in shared folder.".encode())

            # --- Help command ---
            elif data.startswith(b"HELP"):
                help_text = (
                    "SERVER> Commands:\n"
                    "  help                - show this help\n"
                    "  listfiles           - list shared files\n"
                    "  push <file>         - upload a file to host\n"
                    "  pushdir <folder>    - upload a folder as zip\n"
                    "  pull <file>         - download a file\n"
                    "  pulldir <folder>    - download and extract folder\n"
                    "  rmv <name>          - remove file or folder from host\n"
                    "  exit                - leave session"
                )
                send_packet(conn, help_text.encode())

            # --- Chat messages ---
            else:
                msg = data.decode(errors="ignore")
                print(f"{name}> {msg}")
                broadcast(conn, f"{name}> {msg}")

    except Exception as e:
        print(f"[x] Error with {addr}: {e}")
    finally:
        cname = clients.pop(conn, "Unknown")
        conn.close()
        broadcast(None, f"SERVER> {cname} disconnected.")

def start_server():
    """Start TCP server and broadcast host presence."""
    host_ip = get_local_ip()
    print(f"Hosting on {host_ip}:{PORT}")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host_ip, PORT))
    server.listen()

    threading.Thread(target=lambda: accept_clients(server), daemon=True).start()
    threading.Thread(target=lambda: broadcast_host_info(host_ip), daemon=True).start()

    return host_ip

def accept_clients(server):
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

def broadcast_host_info(ip):
    """Send UDP broadcast announcing host availability."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    name = os.getenv("COMPUTERNAME", "HostMachine")
    while True:
        msg = f"HOST:{name}:{ip}".encode()
        sock.sendto(msg, ('<broadcast>', DISCOVERY_PORT))
        time.sleep(BROADCAST_INTERVAL)

# =========================
# Client side
# =========================
def discover_hosts(timeout=5):
    """Discover hosts broadcasting on LAN."""
    print("[Scanning for available hosts...]")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("", DISCOVERY_PORT))
    sock.settimeout(timeout)

    found = {}
    start = time.time()
    while time.time() - start < timeout:
        try:
            data, addr = sock.recvfrom(1024)
            msg = data.decode()
            if msg.startswith("HOST:"):
                _, host_name, host_ip = msg.split(":")
                found[host_ip] = host_name
        except socket.timeout:
            break
        except:
            continue
    sock.close()
    return found

def receive_messages(sock):
    """Listen for incoming messages or files."""
    while True:
        try:
            data = recv_packet(sock)
            if not data:
                break

            if data.startswith(b"FILE:"):
                filename = data.decode().split(":", 1)[1]
                file_data = recv_packet(sock)
                save_path = f"received_{filename}"
                with open(save_path, "wb") as f:
                    f.write(file_data)

                if filename.lower().endswith(".zip"):
                    extract_dir = f"received_{filename[:-4]}"
                    os.makedirs(extract_dir, exist_ok=True)
                    with zipfile.ZipFile(save_path, "r") as zip_ref:
                        zip_ref.extractall(extract_dir)
                    print(f"\n📂 Extracted directory '{extract_dir}' from host.")
                else:
                    print(f"\n📥 Pulled '{filename}' from host.")
            else:
                print(f"\n{data.decode(errors='ignore')}\n> ", end="")
        except:
            break

def client_mode(host_ip=None):
    """Client interface for chat + file operations."""
    if not host_ip:
        hosts = discover_hosts()
        if not hosts:
            print("No hosts found on the network.")
            host_ip = input("Enter host IP manually: ")
        else:
            print("\nDiscovered hosts:")
            for i, (ip, name) in enumerate(hosts.items(), 1):
                print(f" {i}. {name} ({ip})")
            choice = input("\nSelect host number or enter IP: ")
            if choice.isdigit() and 1 <= int(choice) <= len(hosts):
                host_ip = list(hosts.keys())[int(choice) - 1]
            else:
                host_ip = choice.strip()

    name = input("Enter your name: ")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host_ip, PORT))

    send_packet(sock, name.encode())
    threading.Thread(target=receive_messages, args=(sock,), daemon=True).start()

    while True:
        msg = input("> ")
        if msg.lower() == "exit":
            break

        if msg.lower().startswith("push "):
            filename = msg.split(" ", 1)[1]
            if not os.path.exists(filename):
                print("File not found.")
                continue
            send_packet(sock, f"UPLOAD:{os.path.basename(filename)}".encode())
            with open(filename, "rb") as f:
                send_packet(sock, f.read())
            print(f"📤 Uploaded '{filename}' to host.")
            continue

        if msg.lower().startswith("pushdir "):
            foldername = msg.split(" ", 1)[1]
            if not os.path.isdir(foldername):
                print("Folder not found.")
                continue
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zipf:
                for root, _, files in os.walk(foldername):
                    for file in files:
                        full_path = os.path.join(root, file)
                        arcname = os.path.relpath(full_path, foldername)
                        zipf.write(full_path, arcname)
            zip_data = zip_buffer.getvalue()
            zip_filename = f"{os.path.basename(foldername)}.zip"
            send_packet(sock, f"UPLOAD:{zip_filename}".encode())
            send_packet(sock, zip_data)
            print(f"📦 Uploaded folder '{foldername}' as '{zip_filename}'.")
            continue

        if msg.lower().startswith("pull "):
            send_packet(sock, f"PULL:{msg.split(' ', 1)[1]}".encode())
            continue

        if msg.lower().startswith("pulldir "):
            foldername = msg.split(" ", 1)[1]
            send_packet(sock, f"PULL:{foldername}.zip".encode())
            continue

        if msg.lower().startswith("rmv "):
            send_packet(sock, f"RMV:{msg.split(' ', 1)[1]}".encode())
            continue

        if msg.lower() == "listfiles":
            send_packet(sock, b"LISTFILES")
            continue

        if msg.lower() == "help":
            send_packet(sock, b"HELP")
            continue

        send_packet(sock, msg.encode())

    sock.close()

# =========================
# Utility
# =========================
def get_local_ip():
    """Get the LAN IP of this machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

# =========================
# Entry point
# =========================
if __name__ == "__main__":
    mode = input("Host or Join (h/j)? ").strip().lower()
    if mode.startswith("h"):
        host_ip = start_server()
        time.sleep(1)
        print("\n[Host] Server started. Connecting self as client...\n")
        client_mode(host_ip)
    else:
        client_mode()
