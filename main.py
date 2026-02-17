
import sys
import os
import threading
from PySide6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton
from PySide6.QtCore import QObject, Signal, Slot
from PySide6.QtGui import QIcon, QPixmap, QPainter, QColor, QFont, QPen, Qt
from pynput import keyboard
import pyperclip
from urllib.parse import urlparse as urllib_parse
from crypto import load_vault
from widgets import MainView, hotkeyview
from helpers import STYLESHEET, LOGIN_WINDOW_WIDTH, LOGIN_WINDOW_HEIGHT
import ctypes
ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("passwordmanager.app.1")

VAULT_FILE = "vault.json"
# --- Simulated vault functions (replace with yours) ---
def get_domain_from_clipboard():
    url = pyperclip.paste().strip()

    if url.startswith(("http://", "https://")):
        return urllib_parse(url).netloc
    elif url:
        # If it doesn't have protocol, treat it as a domain directly
        # Remove any paths or query strings
        domain = url.split('/')[0] 
        domain = domain.split('?')[0]
        return domain if domain else None
    return None


# --- Custom Signal Emitter (for thread safety) ---
class HotkeyEmitter(QObject):
    domain_detected = Signal(str)  # Emits domain string

# --- Main Window ---
class MainWindow(QMainWindow):
    def __init__(self):  # ✅ FIXED: was _init_
        super().__init__()  # ✅ FIXED: was _init_
        self.emitter = HotkeyEmitter()
        self.emitter.domain_detected.connect(self.show_unlock_popup)
        self.setWindowTitle("Password Manager")
        self.setWindowIcon(self._make_lock_icon())
        self.setMinimumSize(0, 0)  # Allow window to be any size
        self.resize(LOGIN_WINDOW_WIDTH, LOGIN_WINDOW_HEIGHT)  # Set initial window size
        self.setCentralWidget(MainView(self)) 

        # Unlock view (hidden by default)
        self.unlock_widget = None
        self.previous_widget = None  # ✅ Added to avoid AttributeError

    @staticmethod
    def _make_lock_icon():
        pixmap = QPixmap(64, 64)
        pixmap.fill(QColor("#000000"))
        p = QPainter(pixmap)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(QColor("#00FF00"), 4)
        p.setPen(pen)
        p.setBrush(QColor(0, 0, 0, 0))
        # Draw the shackle (arc at top)
        p.drawArc(16, 6, 32, 32, 0, 180 * 16)
        # Draw the body (filled rectangle)
        p.setBrush(QColor("#00FF00"))
        p.drawRoundedRect(10, 28, 44, 30, 4, 4)
        # Draw keyhole (black circle)
        p.setBrush(QColor("#000000"))
        p.setPen(QPen(QColor("#000000"), 1))
        p.drawEllipse(26, 36, 12, 12)
        p.end()
        return QIcon(pixmap)

    @Slot(str)
    def show_unlock_popup(self, domain):
        self.setCentralWidget(hotkeyview(domain, self))  # Show unlock view with domain info
        
# --- Hotkey Listener (runs in background thread) ---
def start_hotkey_listener(emitter):
    def on_activate():
        domain = get_domain_from_clipboard()
        if domain:
            # Emit signal → Qt handles thread-safety!
            emitter.domain_detected.emit(domain)

    with keyboard.GlobalHotKeys({'<ctrl>+<alt>+p': on_activate}) as h:
        h.join()

# --- Main App ---
if __name__ == "__main__":  # ✅ FIXED: was _name_ == "_main_"
    app = QApplication(sys.argv)
    
    app.setStyleSheet(STYLESHEET)
    window = MainWindow()
    window.show()
    
    # Start hotkey listener in background
    emitter = window.emitter  # share the emitteri ddld
    threading.Thread(
        target=start_hotkey_listener,
        args=(emitter,),
        daemon=True
    ).start()
    
    sys.exit(app.exec())