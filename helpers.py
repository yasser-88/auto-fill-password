
import os
import time
import pyperclip
from PySide6.QtWidgets import QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout
from PySide6.QtCore import Qt, QSize, QTimer
from PySide6.QtGui import QFont, QIcon, QPainter, QPixmap, QColor, QPen

from crypto import load_vault, _write_vault

VAULT_FILE = "vault.json"
AUTO_LOCK_TIMEOUT_MS = 2 * 60 * 1000  # 2 minutes, hard lock, no reset

# --- Window size constants ---
LOGIN_WINDOW_WIDTH = 250
LOGIN_WINDOW_HEIGHT = 350
VAULT_WINDOW_WIDTH = 600
VAULT_WINDOW_HEIGHT = 400

# --- Rate-limiting for unlock attempts ---
MAX_UNLOCK_ATTEMPTS = 5
LOCKOUT_SECONDS = 30
_unlock_attempts = 0
_locked_until = 0.0  # timestamp


STYLESHEET = """
    QMainWindow, QWidget {
        background-color: #000000;
    }
    QLabel {
        color: #00FF00;
    }
    QLineEdit {
        background-color: #111111;
        color: #00FF00;
        border: 1px solid #00FF00;
        padding: 8px;
        font-size: 14px;
    }
    QPushButton {
        background-color: #111111;
        color: #00FF00;
        border: 1px solid #00FF00;
        padding: 8px 20px;
        font-size: 14px;
    }
    QPushButton:hover {
        background-color: #003300;
    }
    QPushButton:pressed {
        background-color: #005500;
    }
    QTableWidget {
        background-color: #000000;
        color: #00FF00;
        border: 1px solid #00FF00;
        gridline-color: #004400;
    }
    QTableWidget::item {
        padding: 6px;
    }
    QHeaderView::section {
        background-color: #001a00;
        color: #00FF00;
        border: 1px solid #004400;
        padding: 6px;
        font-weight: bold;
    }
    QMessageBox {
        background-color: #000000;
    }
    QMessageBox QLabel {
        color: #00FF00;
    }
"""


def check_password_strength(password: str) -> str | None:
    """Return an error message if the password is too weak, or None if OK."""
    if len(password) < 8:
        return "Master key must be at least 8 characters."
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    if not (has_upper and has_lower and has_digit):
        return "Must include uppercase, lowercase, and a digit."
    return None


def make_icon(text, color):
    pixmap = QPixmap(24, 24)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(QPen(QColor(color), 2))
    painter.setFont(QFont("Segoe UI Symbol", 14))
    painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, text)
    painter.end()
    return QIcon(pixmap)


def clear_layout(layout):
    while layout.count():
        child = layout.takeAt(0)
        if child.widget():
            child.widget().deleteLater()
        elif child.layout():
            clear_layout(child.layout())


def find_password_for_domain(domain, entries):
    for entry in entries:
        if entry.get("domain") == domain and entry.get("password"):
            return entry.get("password")
    print("the domain is not found in the vault")
    return None


def check_rate_limit() -> str | None:
    """Return an error message if locked out, or None if OK."""
    now = time.time()
    if now < _locked_until:
        remaining = int(_locked_until - now)
        return f"Locked out. Wait {remaining}s."
    return None


def record_failed_attempt() -> str:
    """Record a failed unlock attempt. Returns the error message to display."""
    global _unlock_attempts, _locked_until
    _unlock_attempts += 1
    remaining = MAX_UNLOCK_ATTEMPTS - _unlock_attempts
    if _unlock_attempts >= MAX_UNLOCK_ATTEMPTS:
        _locked_until = time.time() + LOCKOUT_SECONDS
        _unlock_attempts = 0
        return f"Too many attempts. Locked for {LOCKOUT_SECONDS}s."
    else:
        return f"Wrong key. {remaining} attempt(s) left."

def try_unlock(self, domain=None):
    """Attempt to unlock the vault. Works for both MainView and hotkeyview."""
    from widgets import MainView  # lazy import to avoid circular dependency

    rate_msg = check_rate_limit()
    if rate_msg:
        self.error_label.setText(rate_msg)
        return

    self.master_key = self.key_input.text().strip()
    if not self.master_key:
        self.error_label.setText("Please enter a key.")
        return

    try:
        entries = load_vault(self.master_key)
        global _unlock_attempts
        _unlock_attempts = 0
        if isinstance(self, MainView):
            self.bool = False
            self._start_auto_lock()
            self.show_vault_table(entries, self.main_window)
        else:
            password = find_password_for_domain(domain, entries)
            if password:
                pyperclip.copy(password)
                print(f"\u2705 Copied password for {domain}!")
                clear_layout(self.main_layout)
                self.main_layout.addWidget(make_label(f"\u2705 Password for {domain} copied to clipboard!", size=24, bold=True, align_center=True))
                QTimer.singleShot(2000, lambda: self.main_window.minimize_to_tray())
            else:
                print("\u274c No password found.")
                self.entries = entries
                self.show_add_new_login(entries)

    except Exception:
        self.error_label.setText(record_failed_attempt())
        self.key_input.clear()
        self.key_input.setFocus()

def new_login(self):
    """Add a new login entry to the vault."""
    domain = self.domain_input.text().strip()
    username = self.username_input.text().strip()
    password = self.key_input.text().strip()
    if not domain or not password:
        self.error_label.setText("Please fill in password and domain.")
        return
    self.entries.append({
        "domain": domain,
        "username": username if username else "--non added--",
        "password": password
    })
    try:
        _write_vault(self.master_key, self.entries)
        print("\u2705 Login saved!")
    except Exception as e:
        print(f"\u274c Save failed: {e}")
    self.bool = False
    self.show_vault_table(self.entries, self.main_window)


# --- Widget factory functions ---

def make_label(text, size=12, bold=False, align_center=False, word_wrap=False, color=None):
    """Create a styled QLabel."""
    weight = QFont.Weight.Bold if bold else QFont.Weight.Normal
    label = QLabel(text)
    label.setFont(QFont("Consolas", size, weight))
    if align_center:
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    if word_wrap:
        label.setWordWrap(True)
    if color:
        label.setStyleSheet(f"color: {color};")
    return label




def make_input(placeholder="", size=12, password=False, text="", on_click=None):
    """Create a styled QLineEdit."""
    line_edit = QLineEdit(text)
    if password:
        line_edit.setEchoMode(QLineEdit.EchoMode.PasswordEchoOnEdit)
    if placeholder:
        line_edit.setPlaceholderText(placeholder)
    line_edit.setFont(QFont("Consolas", size))
    if on_click:
        line_edit.returnPressed.connect(on_click)
    return line_edit


def make_button(text, size=12, on_click=None):
    """Create a styled QPushButton."""
    btn = QPushButton(text)
    btn.setFont(QFont("Consolas", size))
    if on_click:
        btn.clicked.connect(on_click)
    return btn
