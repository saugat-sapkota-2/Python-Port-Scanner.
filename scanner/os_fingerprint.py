"""Operating system fingerprinting using python-nmap."""

import os
import shutil
from typing import Dict

try:
    import nmap
except Exception:
    nmap = None


def _ensure_nmap_in_path() -> bool:
    """Ensure nmap.exe is discoverable, including common Windows install locations."""
    try:
        if shutil.which("nmap"):
            return True

        candidate_dirs = []
        for env_key in ("ProgramFiles(x86)", "ProgramFiles"):
            base_dir = os.environ.get(env_key, "")
            if base_dir:
                candidate_dirs.append(os.path.join(base_dir, "Nmap"))

        for directory in candidate_dirs:
            nmap_exe = os.path.join(directory, "nmap.exe")
            if os.path.isfile(nmap_exe):
                current_path = os.environ.get("PATH", "")
                os.environ["PATH"] = f"{directory}{os.pathsep}{current_path}"
                return True

        return False
    except Exception:
        return False


def detect_os(target: str) -> Dict[str, str]:
    """Run Nmap OS detection and return the best OS match name and accuracy."""
    if nmap is None:
        return {"name": "Nmap not available", "accuracy": "0"}

    if not _ensure_nmap_in_path():
        return {"name": "Nmap not available", "accuracy": "0"}

    try:
        scanner = nmap.PortScanner()
        scanner.scan(hosts=target, arguments="-O -Pn --osscan-limit")
        hosts = scanner.all_hosts()
        if not hosts:
            return {"name": "No OS match found", "accuracy": "0"}

        host_key = target if target in hosts else hosts[0]
        os_matches = scanner[host_key].get("osmatch", [])
        if not os_matches:
            return {"name": "No OS match found", "accuracy": "0"}

        best_match = os_matches[0]
        os_name = str(best_match.get("name", "")).strip() or "No OS match found"
        return {
            "name": os_name,
            "accuracy": str(best_match.get("accuracy", "0")),
        }
    except Exception as exc:
        lowered = str(exc).lower()
        if "nmap program was not found" in lowered or "no such file or directory" in lowered:
            return {"name": "Nmap not available", "accuracy": "0"}
        if "requires root privileges" in lowered or "dnet" in lowered:
            return {"name": "Nmap needs elevated privileges", "accuracy": "0"}
        return {"name": f"OS detection error: {exc}", "accuracy": "0"}
