"""Flask web application for running TCP port scans with live progress updates."""

from datetime import datetime
import os
import socket
import threading
import time
from typing import Any, Dict, Tuple

from flask import Flask, jsonify, render_template, request, send_from_directory

from scanner.banner_grabber import grab_banners
from scanner.os_fingerprint import detect_os
from scanner.report import generate_report
from scanner.tcp_scanner import scan_ports

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

app = Flask(__name__)

SCAN_STATE: Dict[str, Any] = {
    "status": "idle",
    "progress": 0,
    "current_port": None,
    "message": "Ready",
    "result": None,
    "error": None,
    "report_filename": None,
}
STATE_LOCK = threading.Lock()


def _update_state(**kwargs: Any) -> None:
    """Safely update the global scan state dictionary."""
    with STATE_LOCK:
        SCAN_STATE.update(kwargs)


def _read_state() -> Dict[str, Any]:
    """Safely read and return a copy of the global scan state dictionary."""
    with STATE_LOCK:
        return dict(SCAN_STATE)


def _resolve_target(target: str) -> str:
    """Resolve a hostname or IP string into an IPv4 address."""
    try:
        return socket.gethostbyname(target)
    except Exception as exc:
        raise ValueError(f"Could not resolve target '{target}': {exc}") from exc


def _validate_scan_request(payload: Dict[str, Any]) -> Tuple[str, str, int, int, int]:
    """Validate incoming scan request data and return normalized scan arguments."""
    try:
        target = str(payload.get("target", "")).strip()
        if not target:
            raise ValueError("Target IP or hostname is required.")

        start_port = int(payload.get("start_port", 1))
        end_port = int(payload.get("end_port", 1024))
        thread_count = int(payload.get("thread_count", 100))

        if start_port < 1 or end_port > 65535 or start_port > end_port:
            raise ValueError("Invalid port range. Start must be <= end and between 1-65535.")
        if thread_count < 50 or thread_count > 500:
            raise ValueError("Thread count must be between 50 and 500.")

        resolved_target = _resolve_target(target)
        return target, resolved_target, start_port, end_port, thread_count
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"Invalid request payload: {exc}") from exc


def _build_progress_callback() -> Any:
    """Create and return a callback function that updates progress as ports are scanned."""

    def progress_callback(port: int, scanned: int, total: int) -> None:
        progress = int((scanned / total) * 100) if total else 0
        if scanned < total:
            progress = min(progress, 99)

        _update_state(
            progress=progress,
            current_port=port,
            message=f"Scanning port {port} ({scanned}/{total})...",
        )

    return progress_callback


def _run_scan_worker(
    target: str,
    resolved_target: str,
    start_port: int,
    end_port: int,
    thread_count: int,
) -> None:
    """Run a full scan workflow in a background thread and persist final results."""
    try:
        started_at = time.time()
        open_ports = scan_ports(
            target=resolved_target,
            start_port=start_port,
            end_port=end_port,
            thread_count=thread_count,
            progress_callback=_build_progress_callback(),
        )

        ports_with_banners = grab_banners(resolved_target, open_ports)
        os_info = detect_os(resolved_target)

        duration = round(time.time() - started_at, 2)
        scan_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        report_data = generate_report(
            reports_dir=REPORTS_DIR,
            target=target,
            resolved_target=resolved_target,
            scan_time=scan_time,
            total_ports_scanned=(end_port - start_port) + 1,
            total_open_ports=len(ports_with_banners),
            scan_duration_seconds=duration,
            ports=ports_with_banners,
            os_info=os_info,
        )

        result_payload = {
            "target": target,
            "resolved_target": resolved_target,
            "scan_time": scan_time,
            "total_ports_scanned": (end_port - start_port) + 1,
            "open_ports_found": len(ports_with_banners),
            "scan_duration_seconds": duration,
            "os_info": os_info,
            "ports": ports_with_banners,
        }

        _update_state(
            status="complete",
            progress=100,
            current_port=end_port,
            message="Scan complete",
            result=result_payload,
            error=None,
            report_filename=report_data["filename"],
        )
    except Exception as exc:
        _update_state(
            status="error",
            progress=0,
            current_port=None,
            message="Scan failed.",
            error=str(exc),
            result=None,
            report_filename=None,
        )


@app.get("/")
def index() -> str:
    """Render the main scanner page."""
    try:
        return render_template("index.html")
    except Exception as exc:
        return f"Template rendering failed: {exc}", 500


@app.post("/scan")
def start_scan() -> Tuple[Any, int]:
    """Start a new background port scan and return immediate status."""
    try:
        payload = request.get_json(silent=True) or {}
        target, resolved_target, start_port, end_port, thread_count = _validate_scan_request(payload)

        with STATE_LOCK:
            if SCAN_STATE.get("status") == "running":
                return jsonify({"error": "A scan is already running."}), 409

            SCAN_STATE.update(
                {
                    "status": "running",
                    "progress": 0,
                    "current_port": None,
                    "message": "Starting scan...",
                    "result": None,
                    "error": None,
                    "report_filename": None,
                }
            )

        worker = threading.Thread(
            target=_run_scan_worker,
            args=(target, resolved_target, start_port, end_port, thread_count),
            daemon=True,
        )
        worker.start()

        return jsonify({"status": "running", "message": "Scan started."}), 202
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": f"Could not start scan: {exc}"}), 500


@app.get("/status")
def status() -> Tuple[Any, int]:
    """Return the current scan state as JSON for frontend polling."""
    try:
        return jsonify(_read_state()), 200
    except Exception as exc:
        return jsonify({"status": "error", "error": f"Status unavailable: {exc}"}), 500


@app.get("/download/<filename>")
def download_report(filename: str) -> Tuple[Any, int]:
    """Download a generated JSON report by filename."""
    try:
        safe_name = os.path.basename(filename)
        if safe_name != filename:
            return jsonify({"error": "Invalid filename."}), 400

        file_path = os.path.join(REPORTS_DIR, safe_name)
        if not os.path.isfile(file_path):
            return jsonify({"error": "Report not found."}), 404

        return send_from_directory(REPORTS_DIR, safe_name, as_attachment=True)
    except Exception as exc:
        return jsonify({"error": f"Download failed: {exc}"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
