import os
import subprocess
import sys
import webbrowser

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QPushButton,
    QFileDialog, QLineEdit, QTextEdit, QCheckBox, QMessageBox,
    QHBoxLayout, QFrame
)

from report_builder import build_report


class EnterpriseAccessTraceApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Enterprise Access Trace")
        self.resize(980, 760)

        self.root_path = ""
        self.output_path = ""
        self.report_path = ""

        self.setStyleSheet("""
            QWidget {
                background-color: #0f172a;
                color: #e5e7eb;
                font-family: Segoe UI, Arial, sans-serif;
                font-size: 13px;
            }
            QLabel#title {
                font-size: 32px;
                font-weight: 700;
                color: #f8fafc;
            }
            QLabel#subtitle {
                font-size: 14px;
                color: #94a3b8;
            }
            QFrame#card {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 14px;
            }
            QLabel#sectionTitle {
                font-size: 18px;
                font-weight: 600;
                color: #f8fafc;
            }
            QLabel#pathLabel {
                color: #cbd5e1;
                font-size: 13px;
                padding: 4px 0;
            }
            QLineEdit {
                background-color: #0f172a;
                color: #f8fafc;
                border: 1px solid #475569;
                border-radius: 10px;
                padding: 10px 12px;
            }
            QPushButton {
                background-color: #2563eb;
                color: white;
                border: none;
                border-radius: 10px;
                padding: 10px 14px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #1d4ed8;
            }
            QPushButton#secondary {
                background-color: #334155;
            }
            QPushButton#secondary:hover {
                background-color: #475569;
            }
            QPushButton:disabled {
                background-color: #475569;
                color: #cbd5e1;
            }
            QTextEdit {
                background-color: #0b1220;
                color: #d1d5db;
                border: 1px solid #334155;
                border-radius: 10px;
                padding: 8px;
            }
            QCheckBox {
                color: #e2e8f0;
                spacing: 8px;
            }
        """)

        self.build_ui()

    def build_ui(self):
        outer = QVBoxLayout()
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(16)

        title = QLabel("Enterprise Access Trace")
        title.setObjectName("title")

        subtitle = QLabel("Access Intelligence & Permission Analysis")
        subtitle.setObjectName("subtitle")

        outer.addWidget(title)
        outer.addWidget(subtitle)

        # Config card
        config_card = QFrame()
        config_card.setObjectName("card")
        config_layout = QVBoxLayout()
        config_layout.setContentsMargins(18, 18, 18, 18)
        config_layout.setSpacing(14)

        config_title = QLabel("Scan Configuration")
        config_title.setObjectName("sectionTitle")
        config_layout.addWidget(config_title)

        self.root_label = QLabel("Scan Root Folder: Not selected")
        self.root_label.setObjectName("pathLabel")
        config_layout.addWidget(self.root_label)

        self.root_button = QPushButton("Select Scan Root Folder")
        self.root_button.clicked.connect(self.select_root_folder)
        config_layout.addWidget(self.root_button)

        self.output_label = QLabel("Output Folder: Not selected")
        self.output_label.setObjectName("pathLabel")
        config_layout.addWidget(self.output_label)

        self.output_button = QPushButton("Select Output Folder")
        self.output_button.clicked.connect(self.select_output_folder)
        config_layout.addWidget(self.output_button)

        self.targets_input = QLineEdit()
        self.targets_input.setPlaceholderText(
            "Enter targets separated by commas (e.g. Administrator, Users, Finance-Team)"
        )
        config_layout.addWidget(self.targets_input)

        checkbox_row = QHBoxLayout()
        checkbox_row.setSpacing(20)

        self.include_root_checkbox = QCheckBox("Include root folder")
        self.include_root_checkbox.setChecked(True)
        checkbox_row.addWidget(self.include_root_checkbox)

        self.drift_checkbox = QCheckBox("Run drift analysis")
        self.drift_checkbox.setChecked(True)
        checkbox_row.addWidget(self.drift_checkbox)

        checkbox_row.addStretch()
        config_layout.addLayout(checkbox_row)

        button_row = QHBoxLayout()
        button_row.setSpacing(12)

        self.run_button = QPushButton("Start Scan")
        self.run_button.clicked.connect(self.run_scan)
        button_row.addWidget(self.run_button)

        self.open_report_button = QPushButton("Open Report")
        self.open_report_button.setObjectName("secondary")
        self.open_report_button.clicked.connect(self.open_report)
        self.open_report_button.setEnabled(False)
        button_row.addWidget(self.open_report_button)

        self.open_output_button = QPushButton("Open Output Folder")
        self.open_output_button.setObjectName("secondary")
        self.open_output_button.clicked.connect(self.open_output_folder)
        self.open_output_button.setEnabled(False)
        button_row.addWidget(self.open_output_button)

        button_row.addStretch()
        config_layout.addLayout(button_row)

        config_card.setLayout(config_layout)
        outer.addWidget(config_card)

        # Status card
        status_card = QFrame()
        status_card.setObjectName("card")
        status_layout = QVBoxLayout()
        status_layout.setContentsMargins(18, 18, 18, 18)
        status_layout.setSpacing(12)

        status_title = QLabel("Execution Log")
        status_title.setObjectName("sectionTitle")
        status_layout.addWidget(status_title)

        self.status_label = QLabel("Status: Ready")
        self.status_label.setObjectName("pathLabel")
        status_layout.addWidget(self.status_label)

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        status_layout.addWidget(self.log_box)

        status_card.setLayout(status_layout)
        outer.addWidget(status_card)

        self.setLayout(outer)

    def select_root_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Scan Root Folder")
        if folder:
            self.root_path = folder
            self.root_label.setText(f"Scan Root Folder: {folder}")

    def select_output_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Output Folder")
        if folder:
            self.output_path = folder
            self.output_label.setText(f"Output Folder: {folder}")

    def append_log(self, text):
        self.log_box.append(text)

    def set_status(self, text):
        self.status_label.setText(f"Status: {text}")

    def run_scan(self):
        if not self.root_path:
            QMessageBox.warning(self, "Missing Folder", "Please select a scan root folder.")
            return

        if not self.output_path:
            QMessageBox.warning(self, "Missing Output", "Please select an output folder.")
            return

        scanner_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "scanner", "Invoke-EnterpriseAccessTrace.ps1")
        )

        if not os.path.exists(scanner_path):
            QMessageBox.critical(self, "Missing Scanner", f"Scanner not found at:\n{scanner_path}")
            return

        targets = [t.strip() for t in self.targets_input.text().split(",") if t.strip()]
        targets_csv = ",".join(targets)

        command = [
            "powershell",
            "-ExecutionPolicy", "Bypass",
            "-File", scanner_path,
            "-RootPath", self.root_path,
            "-OutputPath", self.output_path,
            "-TargetsCsv", targets_csv
        ]

        if self.include_root_checkbox.isChecked():
            command.append("-IncludeRoot")

        if self.drift_checkbox.isChecked():
            command.append("-RunDriftAnalysis")

        self.log_box.clear()
        self.append_log("Starting scan...")
        self.append_log("Command: " + " ".join(command))
        self.set_status("Running scan...")
        self.run_button.setEnabled(False)
        self.open_report_button.setEnabled(False)
        self.open_output_button.setEnabled(False)

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False
            )

            if result.stdout:
                self.append_log(result.stdout.strip())

            if result.stderr:
                self.append_log("ERROR: " + result.stderr.strip())

            if result.returncode != 0:
                self.set_status("Scan failed")
                QMessageBox.critical(
                    self,
                    "Scan Failed",
                    f"Scanner returned code {result.returncode}\n\nCheck the execution log for details."
                )
                return

            self.append_log("Building enterprise HTML report...")
            self.report_path = build_report(self.output_path)
            self.append_log(f"Report created: {self.report_path}")

            self.set_status("Completed successfully")
            self.open_report_button.setEnabled(True)
            self.open_output_button.setEnabled(True)
            QMessageBox.information(self, "Success", "Scan completed successfully.")

        except Exception as e:
            self.set_status("Unexpected error")
            QMessageBox.critical(self, "Unexpected Error", str(e))

        finally:
            self.run_button.setEnabled(True)

    def open_report(self):
        if self.report_path and os.path.exists(self.report_path):
            webbrowser.open(self.report_path)
        else:
            QMessageBox.warning(self, "Missing Report", "Report file not found.")

    def open_output_folder(self):
        if self.output_path and os.path.exists(self.output_path):
            os.startfile(self.output_path)
        else:
            QMessageBox.warning(self, "Missing Folder", "Output folder not found.")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))
    window = EnterpriseAccessTraceApp()
    window.show()
    sys.exit(app.exec())