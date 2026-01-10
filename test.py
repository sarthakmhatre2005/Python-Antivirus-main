import sys
import os
import hashlib
import sqlite3
import threading
import time
import datetime
import schedule

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QApplication, QWidget, QPushButton, QLabel, QFileDialog,
    QVBoxLayout, QHBoxLayout, QMessageBox, QProgressBar, QDialog,
    QTableWidget, QTableWidgetItem
)

# ---------------- DATABASE SETUP ---------------- #

def init_signature_db():
    conn = sqlite3.connect("signatures.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS signatures (
            sha256_hash TEXT PRIMARY KEY,
            malware_name TEXT,
            threat_level TEXT
        )
    """)
    conn.commit()
    conn.close()

def init_scan_history_db():
    conn = sqlite3.connect("scan_history.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT,
            folder TEXT,
            files_scanned INTEGER,
            infected_count INTEGER,
            infected_details TEXT
        )
    """)
    conn.commit()
    conn.close()

init_signature_db()
init_scan_history_db()

# ---------------- HASH FUNCTION ---------------- #

def sha256_file(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except:
        return None

# ---------------- SCAN THREAD ---------------- #

class ScanThread(QThread):
    progress = pyqtSignal(int, int)
    finished = pyqtSignal(list, int)
    status = pyqtSignal(str)

    def __init__(self, folder):
        super().__init__()
        self.folder = folder
        self._stop = False

        conn = sqlite3.connect("signatures.db")
        c = conn.cursor()
        c.execute("SELECT sha256_hash, malware_name, threat_level FROM signatures")
        self.signatures = {h: (n, t) for h, n, t in c.fetchall()}
        conn.close()

    def stop(self):
        self._stop = True

    def run(self):
        files = []
        for root, _, fs in os.walk(self.folder):
            for f in fs:
                files.append(os.path.join(root, f))

        infected = []
        total = len(files)

        for i, path in enumerate(files, start=1):
            if self._stop:
                break

            h = sha256_file(path)
            if h and h in self.signatures:
                name, level = self.signatures[h]
                infected.append((path, name, level))

            self.progress.emit(i, total)

        self.finished.emit(infected, total)

# ---------------- SCAN PROGRESS DIALOG ---------------- #

class ScanProgressDialog(QDialog):
    def __init__(self, thread):
        super().__init__()
        self.thread = thread
        self.setWindowTitle("Scanning...")
        self.resize(400, 150)

        self.label = QLabel("Scanning files...")
        self.bar = QProgressBar()
        self.cancel = QPushButton("Cancel")

        layout = QVBoxLayout()
        layout.addWidget(self.label)
        layout.addWidget(self.bar)
        layout.addWidget(self.cancel)
        self.setLayout(layout)

        self.cancel.clicked.connect(self.cancel_scan)

    def cancel_scan(self):
        self.thread.stop()
        self.close()

# ---------------- SCAN HISTORY ---------------- #

class ScanHistoryDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Scan History")
        self.resize(700, 300)

        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(
            ["Date", "Folder", "Files", "Infected", "Details"]
        )

        layout = QVBoxLayout()
        layout.addWidget(self.table)
        self.setLayout(layout)

        self.load()

    def load(self):
        conn = sqlite3.connect("scan_history.db")
        c = conn.cursor()
        c.execute("SELECT date, folder, files_scanned, infected_count, infected_details FROM history")
        rows = c.fetchall()
        conn.close()

        self.table.setRowCount(len(rows))
        for i, row in enumerate(rows):
            for j, val in enumerate(row):
                self.table.setItem(i, j, QTableWidgetItem(str(val)))

# ---------------- MAIN WINDOW ---------------- #

class AntivirusApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Python Antivirus")
        self.resize(400, 250)

        self.scan_btn = QPushButton("Scan Folder")
        self.history_btn = QPushButton("Scan History")
        self.status = QLabel("Ready")

        layout = QVBoxLayout()
        layout.addWidget(self.scan_btn)
        layout.addWidget(self.history_btn)
        layout.addWidget(self.status)
        self.setLayout(layout)

        self.scan_btn.clicked.connect(self.start_scan)
        self.history_btn.clicked.connect(self.show_history)

    def start_scan(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder")
        if not folder:
            return

        self.thread = ScanThread(folder)
        self.dialog = ScanProgressDialog(self.thread)

        self.thread.progress.connect(self.update_progress)
        self.thread.finished.connect(lambda inf, tot: self.scan_finished(folder, inf, tot))

        self.thread.start()
        self.dialog.exec_()

    def update_progress(self, scanned, total):
        self.dialog.bar.setValue(int(scanned / total * 100))
        self.dialog.label.setText(f"Scanned {scanned}/{total}")

    def scan_finished(self, folder, infected, total):
        self.dialog.close()

        conn = sqlite3.connect("scan_history.db")
        c = conn.cursor()
        c.execute(
            "INSERT INTO history VALUES (NULL,?,?,?,?,?)",
            (
                datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                folder,
                total,
                len(infected),
                "\n".join([f"{p} → {n} ({l})" for p, n, l in infected])
            )
        )
        conn.commit()
        conn.close()

        if infected:
            QMessageBox.warning(self, "Threats Found",
                "\n".join([f"{p} → {n} ({l})" for p, n, l in infected]))
        else:
            QMessageBox.information(self, "Clean", "No malware found")

    def show_history(self):
        ScanHistoryDialog().exec_()

# ---------------- RUN ---------------- #

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = AntivirusApp()
    win.show()
    sys.exit(app.exec_())
