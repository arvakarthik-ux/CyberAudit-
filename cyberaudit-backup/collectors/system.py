import platform
import os
import socket
from cyberaudit.utils.privileges import is_admin


def collect():
    """Collect basic system information."""
    try:
        uname = platform.uname()
        info = {
            "node": uname.node,
            "system": uname.system,
            "release": uname.release,
            "version": uname.version,
            "machine": uname.machine,
            "processor": uname.processor,
            "python_user": os.getlogin(),
            "hostname": socket.gethostname(),
            "is_admin": is_admin(),
        }
    except Exception as e:
        info = {"error": str(e)}
    return info
