import platform
import socket
import getpass
import sys
from datetime import datetime

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip


print("=" * 50)
print("          CyberLab Project 001")
print("=" * 50)

print(f"Date & Time : {datetime.now()}")
print(f"User        : {getpass.getuser()}")
print(f"Computer    : {socket.gethostname()}")
print(f"OS          : {platform.system()}")
print(f"Release     : {platform.release()}")
print(f"Python      : {sys.version.split()[0]}")
print(f"IP Address  : {get_local_ip()}")


print("=" * 50)