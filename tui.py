"""Advanced terminal UI for the Python port scanner."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import os
import socket
import threading
import time
from typing import Any, Dict, List

from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Footer, Header, Input, Log, ProgressBar, Static

from scanner.banner_grabber import grab_banners
from scanner.os_fingerprint import detect_os
from scanner.report import generate_report
from scanner.tcp_scanner import scan_ports

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")


@dataclass
class ScanRequest:
    """Normalized scan request details."""

    target: str
    resolved_target: str
    start_port: int
    end_port: int
    thread_count: int


class PortScannerTUI(App[None]):
    """Textual app that provides an advanced terminal workflow for scanning."""

    TITLE = "Python Port Scanner - Advanced TUI"
    SUB_TITLE = "Developer : reinF(Saugat Sapkota)"

    BINDINGS = [
        Binding("s", "start_scan", "Start Scan"),
        Binding("c", "clear_view", "Clear View"),
        Binding("q", "quit", "Quit"),
    ]

    CSS = """
    Screen {
        layout: vertical;
        background: radial-gradient(40% 10%, #173f5f 0%, #102337 45%, #070b12 100%);
        color: #f3f8ff;
    }

    #hero {
        dock: top;
        height: 3;
        content-align: center middle;
        text-style: bold;
        color: #ffe066;
        background: linear-gradient(90deg, #0f3460, #16537e 40%, #0f3460 100%);
        border-bottom: heavy #4ecdc4;
    }

    #body {
        height: 1fr;
        padding: 0 1;
    }

    #left_panel, #right_panel {
        height: 1fr;
        border: round #4ecdc4;
        background: #0f1a2a 90%;
        padding: 1;
        margin: 1 1 1 0;
    }

    #right_panel {
        margin: 1 0 1 1;
    }

    .panel_title {
        text-style: bold;
        color: #ffd166;
        margin-bottom: 1;
    }

    .field_label {
        color: #89c2d9;
        margin: 1 0 0 0;
    }

    Input {
        background: #102438;
        border: round #2a9d8f;
        color: #e6f2ff;
        margin-bottom: 1;
    }

    #button_row {
        height: auto;
        margin-top: 1;
    }

    #start_button {
        width: 1fr;
        margin-right: 1;
    }

    #clear_button {
        width: 1fr;
    }

    #progress_bar {
        margin-top: 1;
        margin-bottom: 1;
    }

    #progress_text {
        color: #bde0fe;
        margin-bottom: 1;
    }

    #summary_box {
        height: 12;
        border: round #3a86ff;
        padding: 1;
        color: #f1faee;
        background: #0a1524;
    }

    #results_table {
        height: 1fr;
        margin-bottom: 1;
        border: round #3a86ff;
    }

    #log_view {
        height: 12;
        border: round #f4a261;
        background: #0a1524;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self.scan_running = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(
            "NETSCOUT ADVANCED TUI  |  Developer : reinF(Saugat Sapkota)",
            id="hero",
        )

        with Horizontal(id="body"):
            with Vertical(id="left_panel"):
                yield Static("Scan Configuration", classes="panel_title")
                yield Static("Target (IP/hostname)", classes="field_label")
                yield Input(placeholder="192.168.1.1 or scanme.nmap.org", id="target_input")

                yield Static("Start Port", classes="field_label")
                yield Input(value="1", id="start_port_input")

                yield Static("End Port", classes="field_label")
                yield Input(value="1024", id="end_port_input")

                yield Static("Threads (50-500)", classes="field_label")
                yield Input(value="100", id="thread_input")

                with Horizontal(id="button_row"):
                    yield Button("Start Scan", variant="success", id="start_button")
                    yield Button("Clear View", variant="warning", id="clear_button")

                yield ProgressBar(total=100, id="progress_bar")
                yield Static("Progress: 0% | Current Port: -", id="progress_text")
                yield Static(self._default_summary(), id="summary_box")

            with Vertical(id="right_panel"):
                yield Static("Open Ports", classes="panel_title")
                yield DataTable(id="results_table")
                yield Static("Live Activity", classes="panel_title")
                yield Log(id="log_view", highlight=False, max_lines=500)

        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#results_table", DataTable)
        table.add_columns("Port", "Protocol", "Service", "Banner")
        table.cursor_type = "row"
        self._log("TUI ready. Press 's' or click Start Scan.")

    def _default_summary(self) -> str:
        return (
            "Scan Summary\n"
            "-----------\n"
            "Target: -\n"
            "Resolved IP: -\n"
            "Scanned Ports: -\n"
            "Open Ports: -\n"
            "Duration: -\n"
            "OS Guess: -\n"
            "Report File: -"
        )

    def _log(self, message: str) -> None:
        log_widget = self.query_one("#log_view", Log)
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_widget.write_line(f"[{timestamp}] {message}")

    def _set_running_state(self, running: bool) -> None:
        self.scan_running = running

        start_button = self.query_one("#start_button", Button)
        target_input = self.query_one("#target_input", Input)
        start_port_input = self.query_one("#start_port_input", Input)
        end_port_input = self.query_one("#end_port_input", Input)
        thread_input = self.query_one("#thread_input", Input)

        start_button.disabled = running
        start_button.label = "Scanning..." if running else "Start Scan"

        target_input.disabled = running
        start_port_input.disabled = running
        end_port_input.disabled = running
        thread_input.disabled = running

    def _resolve_target(self, target: str) -> str:
        try:
            return socket.gethostbyname(target)
        except Exception as exc:
            raise ValueError(f"Could not resolve target '{target}': {exc}") from exc

    def _build_request(self) -> ScanRequest:
        target_value = self.query_one("#target_input", Input).value.strip()
        if not target_value:
            raise ValueError("Target is required.")

        try:
            start_port = int(self.query_one("#start_port_input", Input).value.strip())
            end_port = int(self.query_one("#end_port_input", Input).value.strip())
            thread_count = int(self.query_one("#thread_input", Input).value.strip())
        except ValueError as exc:
            raise ValueError("Ports and thread count must be valid integers.") from exc

        if start_port < 1 or end_port > 65535 or start_port > end_port:
            raise ValueError("Invalid port range. Use 1-65535 and start <= end.")

        if thread_count < 50 or thread_count > 500:
            raise ValueError("Thread count must be between 50 and 500.")

        resolved_target = self._resolve_target(target_value)
        return ScanRequest(
            target=target_value,
            resolved_target=resolved_target,
            start_port=start_port,
            end_port=end_port,
            thread_count=thread_count,
        )

    def _update_progress(self, port: int, scanned: int, total: int) -> None:
        progress = int((scanned / total) * 100) if total else 0
        if scanned < total:
            progress = min(progress, 99)

        progress_bar = self.query_one("#progress_bar", ProgressBar)
        progress_text = self.query_one("#progress_text", Static)

        progress_bar.update(progress=progress)
        progress_text.update(f"Progress: {progress}% | Current Port: {port} ({scanned}/{total})")

    def _clear_table_rows(self) -> None:
        table = self.query_one("#results_table", DataTable)
        try:
            table.clear(columns=False)
        except TypeError:
            table.clear()

    def _reset_visuals(self) -> None:
        self._clear_table_rows()
        self.query_one("#progress_bar", ProgressBar).update(progress=0)
        self.query_one("#progress_text", Static).update("Progress: 0% | Current Port: -")
        self.query_one("#summary_box", Static).update(self._default_summary())

    def _render_results(self, payload: Dict[str, Any], report_filename: str) -> None:
        table = self.query_one("#results_table", DataTable)
        self._clear_table_rows()

        for entry in payload["ports"]:
            banner = str(entry.get("banner", "No banner")).replace("\n", " ").strip()
            if len(banner) > 80:
                banner = f"{banner[:77]}..."
            table.add_row(
                str(entry.get("port", "-")),
                str(entry.get("protocol", "tcp")),
                str(entry.get("service", "unassigned")),
                banner or "No banner",
            )

        summary_text = (
            "Scan Summary\n"
            "-----------\n"
            f"Target: {payload['target']}\n"
            f"Resolved IP: {payload['resolved_target']}\n"
            f"Scanned Ports: {payload['total_ports_scanned']}\n"
            f"Open Ports: {payload['open_ports_found']}\n"
            f"Duration: {payload['scan_duration_seconds']}s\n"
            f"OS Guess: {payload['os_info'].get('name', 'Unknown')}\n"
            f"Report File: {report_filename}"
        )

        self.query_one("#summary_box", Static).update(summary_text)
        self.query_one("#progress_bar", ProgressBar).update(progress=100)
        self.query_one("#progress_text", Static).update("Progress: 100% | Scan complete")

        self._log(
            f"Scan complete. {payload['open_ports_found']} open ports found. Report: {report_filename}"
        )

    def _handle_scan_error(self, error_message: str) -> None:
        self._log(f"Scan failed: {error_message}")
        self.query_one("#progress_text", Static).update("Progress: 0% | Scan failed")

    def _scan_worker(self, request: ScanRequest) -> None:
        try:
            started_at = time.time()
            total_ports = (request.end_port - request.start_port) + 1

            def progress_callback(port: int, scanned: int, total: int) -> None:
                self.call_from_thread(self._update_progress, port, scanned, total)

            self.call_from_thread(
                self._log,
                (
                    f"Scanning {request.target} ({request.resolved_target}) "
                    f"ports {request.start_port}-{request.end_port} with {request.thread_count} threads"
                ),
            )

            open_ports = scan_ports(
                target=request.resolved_target,
                start_port=request.start_port,
                end_port=request.end_port,
                thread_count=request.thread_count,
                progress_callback=progress_callback,
            )

            self.call_from_thread(self._log, "Port discovery complete. Grabbing banners...")
            ports_with_banners = grab_banners(request.resolved_target, open_ports)

            self.call_from_thread(self._log, "Running OS fingerprinting...")
            os_info = detect_os(request.resolved_target)

            duration = round(time.time() - started_at, 2)
            scan_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

            report_data = generate_report(
                reports_dir=REPORTS_DIR,
                target=request.target,
                resolved_target=request.resolved_target,
                scan_time=scan_time,
                total_ports_scanned=total_ports,
                total_open_ports=len(ports_with_banners),
                scan_duration_seconds=duration,
                ports=ports_with_banners,
                os_info=os_info,
            )

            result_payload: Dict[str, Any] = {
                "target": request.target,
                "resolved_target": request.resolved_target,
                "scan_time": scan_time,
                "total_ports_scanned": total_ports,
                "open_ports_found": len(ports_with_banners),
                "scan_duration_seconds": duration,
                "os_info": os_info,
                "ports": ports_with_banners,
            }

            self.call_from_thread(self._render_results, result_payload, report_data["filename"])
        except Exception as exc:
            self.call_from_thread(self._handle_scan_error, str(exc))
        finally:
            self.call_from_thread(self._set_running_state, False)

    @on(Button.Pressed, "#start_button")
    def handle_start_button(self, _event: Button.Pressed) -> None:
        self.action_start_scan()

    @on(Button.Pressed, "#clear_button")
    def handle_clear_button(self, _event: Button.Pressed) -> None:
        self.action_clear_view()

    @on(Input.Submitted)
    def handle_input_submit(self, _event: Input.Submitted) -> None:
        self.action_start_scan()

    def action_start_scan(self) -> None:
        if self.scan_running:
            self._log("A scan is already running.")
            return

        try:
            request = self._build_request()
        except ValueError as exc:
            self._log(str(exc))
            return

        self._reset_visuals()
        self._set_running_state(True)
        self._log("Scan started.")

        worker = threading.Thread(target=self._scan_worker, args=(request,), daemon=True)
        worker.start()

    def action_clear_view(self) -> None:
        if self.scan_running:
            self._log("Cannot clear while a scan is running.")
            return

        self.query_one("#log_view", Log).clear()
        self._reset_visuals()
        self._log("View cleared. Ready for next scan.")


if __name__ == "__main__":
    PortScannerTUI().run()
