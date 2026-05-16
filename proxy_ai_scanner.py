"""
Bug Bounty Analyzer
An HTTP proxy that captures web traffic and uses Ollama (local AI)
to find security vulnerabilities in requests.

Requirements:
    pip install PyQt6 mitmproxy requests
    ollama pull llama3

How to use:
    1. Run: python bugbounty.py
    2. Set your browser proxy to 127.0.0.1:8080
    3. Browse a website — requests appear in the table automatically
    4. Right-click any request → "Send to Ollama" to analyze it
       (Ollama is ONLY called when you manually send a request)
"""

import sys
import json
import asyncio
from datetime import datetime

import requests
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QSplitter, QTableView, QTextEdit,
    QLabel, QPushButton, QVBoxLayout, QHBoxLayout, QTabWidget, QLineEdit,
    QGroupBox, QProgressBar, QDialog, QDialogButtonBox, QFormLayout, QMessageBox,
    QMenu,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QAbstractTableModel, QModelIndex, QTimer
from PyQt6.QtGui import QColor, QFont


# Ollama settings
OLLAMA_URL     = "http://localhost:11434"
OLLAMA_MODEL   = "llama3"
OLLAMA_TIMEOUT = 120

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8080


# ---------------------------------------------------------------------------
# Proxy addon — mitmproxy calls response() for every request that goes through
# ---------------------------------------------------------------------------

class ProxyAddon:
    def __init__(self, queue):
        self.queue = queue
        self.count = 0

    async def response(self, flow):
        self.count += 1
        req = flow.request

        # Build request headers as a string
        req_lines = [f"{req.method} {req.path} HTTP/{req.http_version}"]
        req_lines += [f"{k}: {v}" for k, v in req.headers.items()]

        try:
            req_body = req.text
        except Exception:
            req_body = req.content.decode("utf-8", errors="replace")

        # Build response headers as a string
        resp_headers = ""
        resp_body    = ""
        status_code  = ""

        if flow.response:
            resp = flow.response
            status_code = str(resp.status_code)
            lines = [f"HTTP/{resp.http_version} {resp.status_code} {resp.reason}"]
            lines += [f"{k}: {v}" for k, v in resp.headers.items()]
            resp_headers = "\r\n".join(lines)
            try:
                resp_body = resp.text
            except Exception:
                resp_body = resp.content.decode("utf-8", errors="replace")

        await self.queue.put({
            "id":             str(self.count),
            "method":         req.method,
            "url":            req.pretty_url,
            "statusCode":     status_code,
            "requestHeader":  "\r\n".join(req_lines),
            "requestBody":    req_body,
            "responseHeader": resp_headers,
            "responseBody":   resp_body,
            "timestamp":      datetime.now().strftime("%H:%M:%S"),
        })


# ---------------------------------------------------------------------------
# Proxy thread — runs mitmproxy in the background so the UI stays responsive
# ---------------------------------------------------------------------------

class ProxyThread(QThread):
    started_ok = pyqtSignal(str)
    error      = pyqtSignal(str)

    def __init__(self, queue, host, port):
        super().__init__()
        self.queue = queue
        self.host  = host
        self.port  = port
        self._loop = None

    def run(self):
        from mitmproxy.tools import dump
        from mitmproxy import options

        async def start_proxy():
            opts   = options.Options(listen_host=self.host, listen_port=self.port)
            master = dump.DumpMaster(opts, with_termlog=False, with_dumper=False)
            master.addons.add(ProxyAddon(self.queue))
            self.started_ok.emit(f"{self.host}:{self.port}")
            await master.run()

        try:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            self._loop.run_until_complete(start_proxy())
        except OSError as e:
            self.error.emit(f"Cannot start proxy: {e}\n\nIs port {self.port} already in use?")
        except Exception as e:
            self.error.emit(f"Proxy error: {e}")

    def stop(self):
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)


# ---------------------------------------------------------------------------
# Table model — feeds captured requests into the QTableView
# ---------------------------------------------------------------------------

class HistoryModel(QAbstractTableModel):
    COLUMNS = ["#", "Time", "Method", "Status", "URL"]

    METHOD_COLORS = {
        "GET":    "#61AFEF",
        "POST":   "#98C379",
        "PUT":    "#E5C07B",
        "DELETE": "#E06C75",
        "PATCH":  "#C678DD",
    }

    STATUS_COLORS = {
        "2": "#98C379",
        "3": "#61AFEF",
        "4": "#E5C07B",
        "5": "#E06C75",
    }

    def __init__(self):
        super().__init__()
        self.rows = []

    def rowCount(self, parent=QModelIndex()):
        return len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return len(self.COLUMNS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.COLUMNS[section]

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or index.row() >= len(self.rows):
            return None

        row = self.rows[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            keys = ["id", "timestamp", "method", "statusCode", "url"]
            return row.get(keys[col], "")

        if role == Qt.ItemDataRole.ForegroundRole:
            if col == 2:
                color = self.METHOD_COLORS.get(row.get("method", ""), "#ABB2BF")
                return QColor(color)
            if col == 3:
                status = row.get("statusCode", "")
                color  = self.STATUS_COLORS.get(status[0] if status else "", "#ABB2BF")
                return QColor(color)

        if role == Qt.ItemDataRole.UserRole:
            return row

    def append(self, flow):
        pos = len(self.rows)
        self.beginInsertRows(QModelIndex(), pos, pos)
        self.rows.append(flow)
        self.endInsertRows()

    def clear(self):
        self.beginResetModel()
        self.rows.clear()
        self.endResetModel()

    def get_row(self, index):
        if 0 <= index < len(self.rows):
            return self.rows[index]
        return None


# ---------------------------------------------------------------------------
# AI worker — sends the request to Ollama and streams the response back
# ---------------------------------------------------------------------------

class AIWorker(QThread):
    chunk_received = pyqtSignal(str)
    finished       = pyqtSignal(str)
    error          = pyqtSignal(str)

    def __init__(self, flow, ollama_url, model, timeout):
        super().__init__()
        self.flow       = flow
        self.ollama_url = ollama_url
        self.model      = model
        self.timeout    = timeout
        self.cancelled  = False

    def cancel(self):
        self.cancelled = True

    def build_prompt(self):
        req_header  = self.flow.get("requestHeader",  "(none)")
        req_body    = self.flow.get("requestBody",    "(empty)")
        resp_header = self.flow.get("responseHeader", "(none)")
        resp_body   = self.flow.get("responseBody",   "(empty)")

        # Trim large bodies so we don't exceed the model's context
        if len(req_body) > 3000:
            req_body = req_body[:3000] + "...[truncated]"
        if len(resp_body) > 5000:
            resp_body = resp_body[:5000] + "...[truncated]"

        prompt = f"""You are a security researcher doing a bug bounty analysis.
Analyze this HTTP request and response for security vulnerabilities.

=== REQUEST ===
{req_header}

{req_body}

=== RESPONSE ===
{resp_header}

{resp_body}

=== TASK ===
Check for these common vulnerabilities:
- SQL injection or command injection
- Broken authentication or weak session tokens
- Sensitive data exposure (API keys, passwords, tokens in responses)
- Missing security headers (CSP, HSTS, X-Frame-Options)
- IDOR (predictable IDs in URLs)
- CORS misconfiguration
- Information disclosure (stack traces, debug output, server versions)
- Input validation issues

For each finding:
  - Vulnerability: name it
  - Evidence: quote the specific header/parameter/value
  - Risk: Low / Medium / High / Critical
  - Fix: one clear recommendation

If nothing looks suspicious, say so. Be concise and actionable."""

        return prompt

    def run(self):
        url     = self.ollama_url.rstrip("/") + "/api/chat"
        payload = {
            "model":    self.model,
            "stream":   True,
            "messages": [{"role": "user", "content": self.build_prompt()}],
        }

        try:
            parts = []
            with requests.post(url, json=payload, stream=True, timeout=self.timeout) as response:
                if response.status_code != 200:
                    self.error.emit(
                        f"Ollama returned HTTP {response.status_code}\n\n"
                        f"Make sure the model is downloaded:  ollama pull {self.model}\n\n"
                        f"Response: {response.text[:300]}"
                    )
                    return

                # Ollama sends one JSON object per line
                for line in response.iter_lines():
                    if self.cancelled:
                        self.finished.emit("".join(parts) + "\n\n[Cancelled]")
                        return
                    if not line:
                        continue
                    try:
                        obj  = json.loads(line)
                        text = obj.get("message", {}).get("content", "")
                        if text:
                            parts.append(text)
                            self.chunk_received.emit(text)
                        if obj.get("done"):
                            break
                    except json.JSONDecodeError:
                        continue

            self.finished.emit("".join(parts))

        except requests.exceptions.ConnectionError:
            self.error.emit(
                f"Could not connect to Ollama at {self.ollama_url}\n\n"
                "Make sure Ollama is running:  ollama serve"
            )
        except requests.exceptions.Timeout:
            self.error.emit(
                f"Ollama timed out after {self.timeout}s.\n\n"
                "The model may still be loading — try again in a moment."
            )
        except Exception as e:
            self.error.emit(f"Error: {e}")


# ---------------------------------------------------------------------------
# Settings dialog — lets the user change Ollama URL, model, and timeout
# ---------------------------------------------------------------------------

class SettingsDialog(QDialog):
    def __init__(self, url, model, timeout, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumWidth(400)
        self.build_ui(url, model, timeout)

    def build_ui(self, url, model, timeout):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        form = QFormLayout()
        form.setContentsMargins(8, 8, 8, 8)

        self.url_input     = QLineEdit(url)
        self.model_input   = QLineEdit(model)
        self.timeout_input = QLineEdit(str(timeout))

        self.url_input.setPlaceholderText("http://localhost:11434")
        self.model_input.setPlaceholderText("llama3")
        self.timeout_input.setPlaceholderText("120")

        form.addRow("Ollama URL:", self.url_input)
        form.addRow("Model:",      self.model_input)
        form.addRow("Timeout (s):", self.timeout_input)

        hint = QLabel("Download a model first:  <code>ollama pull llama3</code>")
        hint.setTextFormat(Qt.TextFormat.RichText)
        hint.setStyleSheet("color: #5C6370; font-size: 11px;")
        form.addRow("", hint)

        layout.addLayout(form)

        test_btn = QPushButton("Test Connection")
        test_btn.clicked.connect(self.test_connection)
        layout.addWidget(test_btn)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def test_connection(self):
        url = self.url_input.text().strip() or "http://localhost:11434"
        try:
            r = requests.get(f"{url}/api/tags", timeout=5)
            if r.status_code < 400:
                QMessageBox.information(self, "Test", f"Connected to Ollama at {url}")
            else:
                QMessageBox.warning(self, "Test", f"Ollama replied with HTTP {r.status_code}")
        except requests.exceptions.ConnectionError:
            QMessageBox.critical(self, "Test",
                f"Cannot connect to {url}\nIs Ollama running?  ollama serve")
        except requests.exceptions.Timeout:
            QMessageBox.critical(self, "Test", "Connection timed out.")

    def get_values(self):
        url   = self.url_input.text().strip()   or "http://localhost:11434"
        model = self.model_input.text().strip() or "llama3"
        try:
            timeout = int(self.timeout_input.text().strip())
        except ValueError:
            timeout = 120
        return url, model, timeout


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Bug Bounty Analyzer")
        self.resize(1300, 820)

        self.ollama_url     = OLLAMA_URL
        self.ollama_model   = OLLAMA_MODEL
        self.ollama_timeout = OLLAMA_TIMEOUT

        self.flow_queue   = asyncio.Queue()
        self.ai_worker    = None
        self.proxy_thread = None
        # The flow the user explicitly chose to send to Ollama.
        # This is only set via right-click → "Send to Ollama", never automatically.
        self.queued_flow  = None

        self.build_ui()
        self.apply_dark_theme()

        # Check for new captured requests every 300ms
        self.poll_timer = QTimer(self)
        self.poll_timer.setInterval(300)
        self.poll_timer.timeout.connect(self.drain_queue)
        self.poll_timer.start()

        self.statusBar().showMessage("Ready — start the proxy, then browse a site")

    def build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(6, 6, 6, 6)

        # --- Toolbar ---
        toolbar = QHBoxLayout()

        self.proxy_status = QLabel("⬤  Proxy: stopped")
        self.proxy_status.setStyleSheet("color: #E06C75; font-weight: bold;")

        self.start_btn    = QPushButton("▶  Start Proxy")
        self.stop_btn     = QPushButton("⏹  Stop Proxy")
        self.clear_btn    = QPushButton("🗑  Clear History")
        self.settings_btn = QPushButton("⚙  Settings")
        self.stop_btn.setEnabled(False)

        self.filter_box = QLineEdit()
        self.filter_box.setPlaceholderText("Filter URLs...")
        self.filter_box.textChanged.connect(self.apply_filter)

        self.request_count = QLabel("0 requests")

        self.start_btn.clicked.connect(self.start_proxy)
        self.stop_btn.clicked.connect(self.stop_proxy)
        self.clear_btn.clicked.connect(self.clear_history)
        self.settings_btn.clicked.connect(self.open_settings)

        toolbar.addWidget(self.proxy_status)
        toolbar.addSpacing(12)
        toolbar.addWidget(self.start_btn)
        toolbar.addWidget(self.stop_btn)
        toolbar.addWidget(self.clear_btn)
        toolbar.addSpacing(20)
        toolbar.addWidget(QLabel("Filter:"))
        toolbar.addWidget(self.filter_box, stretch=1)
        toolbar.addSpacing(12)
        toolbar.addWidget(self.request_count)
        toolbar.addSpacing(12)
        toolbar.addWidget(self.settings_btn)
        root.addLayout(toolbar)

        # --- Main split: left = history table, right = request/response + AI ---
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        root.addWidget(main_splitter, stretch=1)

        # Left: proxy history table
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.addWidget(QLabel("  Proxy History"))

        self.history_model = HistoryModel()
        self.table = QTableView()
        self.table.setModel(self.history_model)
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self.table.setSortingEnabled(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(0, 50)
        self.table.setColumnWidth(1, 70)
        self.table.setColumnWidth(2, 65)
        self.table.setColumnWidth(3, 55)
        self.table.selectionModel().selectionChanged.connect(self.on_row_selected)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        left_layout.addWidget(self.table)
        main_splitter.addWidget(left_widget)

        # Right: request/response tabs + AI panel below
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)

        mono_font = QFont("Consolas", 10)

        self.detail_tabs = QTabWidget()

        self.req_view = QTextEdit()
        self.req_view.setReadOnly(True)
        self.req_view.setFont(mono_font)
        self.req_view.setPlaceholderText("Select a row to see the request...")

        self.resp_view = QTextEdit()
        self.resp_view.setReadOnly(True)
        self.resp_view.setFont(mono_font)
        self.resp_view.setPlaceholderText("Select a row to see the response...")

        self.detail_tabs.addTab(self.req_view,  "Request")
        self.detail_tabs.addTab(self.resp_view, "Response")

        # AI analysis panel
        ai_group = QGroupBox("AI Security Analysis  (Ollama)")
        ai_layout = QVBoxLayout(ai_group)

        # Shows which request is queued — only set by right-click, not automatically
        self.queued_label = QLabel("No request queued  —  right-click a row to send one to Ollama")
        self.queued_label.setStyleSheet("color: #5C6370; font-size: 11px; padding: 2px 4px;")
        ai_layout.addWidget(self.queued_label)

        btn_row = QHBoxLayout()
        self.analyze_btn = QPushButton("🚀  Send to Ollama")
        self.cancel_btn  = QPushButton("✖  Cancel")
        self.cancel_btn.setEnabled(False)
        self.analyze_btn.setEnabled(False)   # disabled until user right-clicks a row
        self.analyze_btn.clicked.connect(self.run_analysis)
        self.cancel_btn.clicked.connect(self.cancel_analysis)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setVisible(False)
        self.progress_bar.setMaximumHeight(6)

        btn_row.addWidget(self.analyze_btn)
        btn_row.addWidget(self.cancel_btn)
        btn_row.addStretch()
        ai_layout.addLayout(btn_row)
        ai_layout.addWidget(self.progress_bar)

        self.ai_output = QTextEdit()
        self.ai_output.setReadOnly(True)
        self.ai_output.setFont(mono_font)
        self.ai_output.setPlaceholderText("Right-click a request in the table → Send to Ollama to analyze it here...")
        ai_layout.addWidget(self.ai_output)

        right_splitter = QSplitter(Qt.Orientation.Vertical)
        right_splitter.addWidget(self.detail_tabs)
        right_splitter.addWidget(ai_group)
        right_splitter.setSizes([300, 350])

        right_layout.addWidget(right_splitter)
        main_splitter.addWidget(right_widget)
        main_splitter.setSizes([420, 880])

    # --- Proxy controls ---

    def start_proxy(self):
        self.proxy_thread = ProxyThread(self.flow_queue, PROXY_HOST, PROXY_PORT)
        self.proxy_thread.started_ok.connect(self.on_proxy_started)
        self.proxy_thread.error.connect(self.on_proxy_error)
        self.proxy_thread.start()
        self.start_btn.setEnabled(False)
        self.statusBar().showMessage(f"Starting proxy on {PROXY_HOST}:{PROXY_PORT}...")

    def stop_proxy(self):
        if self.proxy_thread:
            self.proxy_thread.stop()
            self.proxy_thread = None
        self.proxy_status.setText("⬤  Proxy: stopped")
        self.proxy_status.setStyleSheet("color: #E06C75; font-weight: bold;")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.statusBar().showMessage("Proxy stopped")

    def on_proxy_started(self, addr):
        self.proxy_status.setText(f"⬤  Proxy: {addr}")
        self.proxy_status.setStyleSheet("color: #98C379; font-weight: bold;")
        self.stop_btn.setEnabled(True)
        self.statusBar().showMessage(
            f"Proxy running on {addr}  —  Set your browser proxy to {addr}")

    def on_proxy_error(self, message):
        self.start_btn.setEnabled(True)
        self.proxy_status.setText("⬤  Proxy: error")
        self.proxy_status.setStyleSheet("color: #E06C75; font-weight: bold;")
        self.ai_output.setPlainText(f"Proxy error:\n\n{message}")
        self.statusBar().showMessage("Proxy failed")

    # --- Queue draining ---

    def drain_queue(self):
        count = 0
        while True:
            try:
                flow = self.flow_queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            self.history_model.append(flow)
            count += 1
        if count:
            self.request_count.setText(f"{self.history_model.rowCount()} requests")

    # --- Table interaction ---

    def on_row_selected(self):
        indexes = self.table.selectionModel().selectedRows()
        if not indexes:
            return
        flow = self.history_model.get_row(indexes[0].row())
        if not flow:
            return
        # Clicking a row just previews it — it does NOT send anything to Ollama
        request_text  = (flow.get("requestHeader", "") + "\r\n\r\n" + flow.get("requestBody", "")).strip()
        response_text = (flow.get("responseHeader", "") + "\r\n\r\n" + flow.get("responseBody", "")).strip()
        self.req_view.setPlainText(request_text)
        self.resp_view.setPlainText(response_text)
        self.statusBar().showMessage(
            f"{flow.get('method')} {flow.get('url')}  [{flow.get('statusCode', '?')}]  "
            f"— Right-click to send to Ollama")

    def show_context_menu(self, pos):
        """Right-click menu on the table — the only way to queue a request for Ollama."""
        indexes = self.table.selectionModel().selectedRows()
        if not indexes:
            return
        flow = self.history_model.get_row(indexes[0].row())
        if not flow:
            return

        menu = QMenu(self)
        send_action = menu.addAction("🚀  Send to Ollama")
        action = menu.exec(self.table.viewport().mapToGlobal(pos))

        if action == send_action:
            self.queued_flow = flow
            method = flow.get("method", "?")
            url    = flow.get("url", "?")
            # Truncate long URLs for the label
            short_url = url if len(url) <= 80 else url[:77] + "..."
            self.queued_label.setText(f"Queued:  {method}  {short_url}")
            self.queued_label.setStyleSheet("color: #98C379; font-size: 11px; padding: 2px 4px;")
            self.analyze_btn.setEnabled(True)
            self.statusBar().showMessage(f"Queued for Ollama: {method} {url}")

    def apply_filter(self, text):
        text = text.strip().lower()
        for row in range(self.history_model.rowCount()):
            flow = self.history_model.get_row(row)
            url  = (flow.get("url", "") if flow else "").lower()
            self.table.setRowHidden(row, bool(text) and text not in url)

    def clear_history(self):
        self.history_model.clear()
        self.req_view.clear()
        self.resp_view.clear()
        self.ai_output.clear()
        self.request_count.setText("0 requests")
        self.queued_flow = None
        self.queued_label.setText("No request queued  —  right-click a row to send one to Ollama")
        self.queued_label.setStyleSheet("color: #5C6370; font-size: 11px; padding: 2px 4px;")
        self.analyze_btn.setEnabled(False)

    # --- AI analysis ---

    def run_analysis(self):
        # Only runs on the flow the user explicitly queued via right-click
        if not self.queued_flow:
            self.ai_output.setPlainText("No request queued.\nRight-click a row in the table and choose 'Send to Ollama'.")
            return

        if self.ai_worker and self.ai_worker.isRunning():
            self.ai_worker.cancel()

        method = self.queued_flow.get("method", "?")
        url    = self.queued_flow.get("url", "?")

        self.ai_output.setPlainText(f"Sending to Ollama...\n\n{method} {url}\n\n")
        self.progress_bar.setVisible(True)
        self.analyze_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)

        self.ai_worker = AIWorker(self.queued_flow, self.ollama_url, self.ollama_model, self.ollama_timeout)
        self.ai_worker.chunk_received.connect(self.on_chunk)
        self.ai_worker.finished.connect(self.on_analysis_done)
        self.ai_worker.error.connect(self.on_analysis_error)
        self.ai_worker.start()

        self.statusBar().showMessage(f"Sent to Ollama ({self.ollama_model}): {method} {url}")

    def on_chunk(self, text):
        cursor = self.ai_output.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        cursor.insertText(text)
        self.ai_output.setTextCursor(cursor)

    def on_analysis_done(self, _):
        self.progress_bar.setVisible(False)
        self.analyze_btn.setEnabled(self.queued_flow is not None)
        self.cancel_btn.setEnabled(False)
        self.statusBar().showMessage("Analysis complete")

    def on_analysis_error(self, message):
        self.ai_output.setPlainText(message)
        self.progress_bar.setVisible(False)
        self.analyze_btn.setEnabled(self.queued_flow is not None)
        self.cancel_btn.setEnabled(False)
        self.statusBar().showMessage("Analysis failed")

    def cancel_analysis(self):
        if self.ai_worker:
            self.ai_worker.cancel()
        self.cancel_btn.setEnabled(False)
        self.statusBar().showMessage("Analysis cancelled")

    # --- Settings ---

    def open_settings(self):
        dialog = SettingsDialog(
            self.ollama_url, self.ollama_model, self.ollama_timeout, parent=self)
        dialog.setStyleSheet(self.styleSheet())
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.ollama_url, self.ollama_model, self.ollama_timeout = dialog.get_values()
            self.setWindowTitle(f"Bug Bounty Analyzer  —  {self.ollama_model} @ {self.ollama_url}")
            self.statusBar().showMessage(
                f"Settings saved — using {self.ollama_model} at {self.ollama_url}")

    # --- Cleanup ---

    def closeEvent(self, event):
        self.poll_timer.stop()
        if self.proxy_thread:
            self.proxy_thread.stop()
        if self.ai_worker and self.ai_worker.isRunning():
            self.ai_worker.cancel()
        event.accept()

    # --- Dark theme ---

    def apply_dark_theme(self):
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #282C34;
                color: #ABB2BF;
                font-family: "Segoe UI", Arial, sans-serif;
                font-size: 13px;
            }
            QTableView {
                background-color: #21252B;
                alternate-background-color: #282C34;
                gridline-color: #3E4451;
                selection-background-color: #3A3F4B;
                selection-color: #E5C07B;
                border: 1px solid #3E4451;
            }
            QTableView::item { padding: 3px 6px; }
            QHeaderView::section {
                background-color: #21252B;
                color: #61AFEF;
                border: none;
                border-bottom: 2px solid #3E4451;
                padding: 4px 8px;
                font-weight: bold;
            }
            QTabWidget::pane { border: 1px solid #3E4451; }
            QTabBar::tab {
                background: #21252B;
                color: #ABB2BF;
                padding: 6px 18px;
                border: 1px solid #3E4451;
                border-bottom: none;
            }
            QTabBar::tab:selected {
                background: #282C34;
                color: #E5C07B;
                border-bottom: 2px solid #E5C07B;
            }
            QTextEdit {
                background-color: #1E2127;
                color: #ABB2BF;
                border: 1px solid #3E4451;
            }
            QPushButton {
                background-color: #3A3F4B;
                color: #ABB2BF;
                border: 1px solid #4B5263;
                padding: 5px 14px;
                border-radius: 4px;
            }
            QPushButton:hover   { background-color: #4B5263; color: #E5C07B; }
            QPushButton:pressed { background-color: #E5C07B; color: #282C34; }
            QPushButton:disabled { color: #4B5263; }
            QLineEdit {
                background-color: #1E2127;
                color: #ABB2BF;
                border: 1px solid #4B5263;
                padding: 4px 8px;
                border-radius: 3px;
            }
            QGroupBox {
                border: 1px solid #3E4451;
                border-radius: 4px;
                margin-top: 8px;
                padding-top: 4px;
                font-weight: bold;
                color: #61AFEF;
            }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; }
            QProgressBar { border: none; background: #21252B; }
            QProgressBar::chunk { background-color: #E5C07B; }
            QSplitter::handle { background: #3E4451; }
            QStatusBar { border-top: 1px solid #3E4451; color: #5C6370; }
            QScrollBar:vertical { background: #21252B; width: 10px; border: none; }
            QScrollBar::handle:vertical {
                background: #4B5263; border-radius: 5px; min-height: 20px;
            }
            QDialog { background-color: #282C34; }
        """)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Bug Bounty Analyzer")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
