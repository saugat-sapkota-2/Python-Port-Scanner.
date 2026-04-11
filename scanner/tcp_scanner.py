"""TCP scanning utilities for discovering open ports."""

from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
from typing import Any, Callable, Dict, List, Optional


def _scan_single_port(target: str, port: int, timeout: float = 1.0) -> Optional[Dict[str, Any]]:
    """Attempt a TCP connection to a single port and return service info if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            if result != 0:
                return None

        try:
            service_name = socket.getservbyport(port, "tcp")
        except OSError:
            service_name = "unassigned"

        return {
            "port": port,
            "protocol": "tcp",
            "service": service_name,
        }
    except Exception:
        return None


def scan_ports(
    target: str,
    start_port: int,
    end_port: int,
    thread_count: int = 100,
    progress_callback: Optional[Callable[[int, int, int], None]] = None,
) -> List[Dict[str, Any]]:
    """Scan a target for open TCP ports with a thread pool and return open port metadata."""
    try:
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            raise ValueError("Invalid port range. Use values between 1 and 65535.")
        if thread_count < 1:
            raise ValueError("Thread count must be at least 1.")

        ports_to_scan = list(range(start_port, end_port + 1))
        total_ports = len(ports_to_scan)
        scanned_ports = 0
        open_ports: List[Dict[str, Any]] = []

        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = {
                executor.submit(_scan_single_port, target, port): port
                for port in ports_to_scan
            }

            for future in as_completed(futures):
                current_port = futures[future]
                scanned_ports += 1

                if progress_callback is not None:
                    progress_callback(current_port, scanned_ports, total_ports)

                result = future.result()
                if result is not None:
                    open_ports.append(result)

        open_ports.sort(key=lambda item: int(item["port"]))
        return open_ports
    except ValueError:
        raise
    except Exception as exc:
        raise RuntimeError(f"Port scan failed: {exc}") from exc
