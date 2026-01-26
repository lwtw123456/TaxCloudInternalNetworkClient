import re
import ctypes
import threading
from datetime import datetime

class LASTINPUTINFO(ctypes.Structure):
    _fields_ = [
        ('cbSize', ctypes.c_uint),
        ('dwTime', ctypes.c_uint),
    ]

def get_idle_seconds():
    try:
        last_input_info = LASTINPUTINFO()
        last_input_info.cbSize = ctypes.sizeof(last_input_info)
        if not ctypes.windll.user32.GetLastInputInfo(ctypes.byref(last_input_info)):
            return None

        tick_count = ctypes.windll.kernel32.GetTickCount()
        idle_ms = tick_count - last_input_info.dwTime
        return idle_ms / 1000.0
    except Exception:
        return None

def is_valid_host(host):
    host = host.lower()
    if host.startswith("http://"):
        host = host[len("http://"):]
    elif host.startswith("https://"):
        host = host[len("https://"):]
    host = host.rstrip("/")
    if not host:
        return False
    if ":" in host:
        part, port = host.rsplit(":", 1)
        if not port.isdigit() or not (0 <= int(port) <= 65535):
            return False
        host = part
    ipv4 = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4, host):
        return all(0 <= int(x) <= 255 for x in host.split("."))

    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, host))
    
def get_filename_suffix():
    return datetime.now().strftime("%m%d%H%M%S")
    
def run_async(func, *args):
    t = threading.Thread(target=func, args=args, daemon=True)
    t.start()
    return t
    
def decode_response_content(content):
    encodings = ['utf-8', 'gbk', 'gb2312', 'utf-16', 'latin-1']
    for enc in encodings:
        try:
            return content.decode(enc)
        except:
            continue
    return