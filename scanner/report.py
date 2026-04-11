"""JSON report generation for completed scans."""

from datetime import datetime
import json
import os
from typing import Any, Dict, List


def _sanitize_target(target: str) -> str:
    """Create a filesystem-safe target string for report filenames."""
    return "".join(character if character.isalnum() or character in "._-" else "_" for character in target)


def generate_report(
    reports_dir: str,
    target: str,
    resolved_target: str,
    scan_time: str,
    total_ports_scanned: int,
    total_open_ports: int,
    scan_duration_seconds: float,
    ports: List[Dict[str, Any]],
    os_info: Dict[str, str],
) -> Dict[str, Any]:
    """Write a scan result report as JSON and return report metadata."""
    try:
        os.makedirs(reports_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = _sanitize_target(target)
        filename = f"scan_{safe_target}_{timestamp}.json"
        filepath = os.path.join(reports_dir, filename)

        report_data = {
            "target": target,
            "resolved_target": resolved_target,
            "scan_time": scan_time,
            "total_ports_scanned": total_ports_scanned,
            "total_open_ports": total_open_ports,
            "scan_duration_seconds": scan_duration_seconds,
            "ports": ports,
            "os_info": os_info,
        }

        with open(filepath, "w", encoding="utf-8") as report_file:
            json.dump(report_data, report_file, indent=2)

        return {
            "filename": filename,
            "path": filepath,
            "report": report_data,
        }
    except Exception as exc:
        raise RuntimeError(f"Could not write report: {exc}") from exc
