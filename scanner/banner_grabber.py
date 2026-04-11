"""Banner grabbing utilities for open TCP ports."""

import socket
from typing import Any, Dict, List


def grab_banner(target: str, port: int, timeout: float = 2.0) -> str:
    """Connect to an open port and return up to 1024 bytes of banner text."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((target, port))
            banner = sock.recv(1024)

        if not banner:
            return "No banner"

        decoded = banner.decode("utf-8", errors="ignore").strip()
        return decoded if decoded else "No banner"
    except Exception:
        return "No banner"


def grab_banners(target: str, open_ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Attach a banner string to each open port record."""
    try:
        results: List[Dict[str, Any]] = []
        for port_info in open_ports:
            port_value = int(port_info.get("port", 0))
            banner = grab_banner(target, port_value)
            results.append(
                {
                    "port": port_value,
                    "protocol": str(port_info.get("protocol", "tcp")),
                    "service": str(port_info.get("service", "unassigned")),
                    "banner": banner,
                }
            )
        return results
    except Exception as exc:
        raise RuntimeError(f"Banner grabbing failed: {exc}") from exc
