
import sys
import os
import threading
from PySide6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton
from PySide6.QtCore import QObject, Signal, Slot
from pynput import keyboard
import pyperclip
from urllib.parse import urlparse
from crypto import load_vault
from widgets import MainView ,hotkeyview , clear_layout , STYLESHEET , find_password_for_domain
VAULT_FILE = "vault.json"
# --- Simulated vault functions (replace with yours) ---
def get_domain_from_clipboard():
    url = pyperclip.paste().strip()

    if url.startswith(("http://", "https://")):
        return urlparse(url).netloc
    elif url:
        # If it doesn't have protocol, treat it as a domain directly
        # Remove any paths or query strings
        domain = url.split('/')[0].split('?')[0]
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
       
        
        self.setCentralWidget(MainView()) 

        # Unlock view (hidden by default)
        self.unlock_widget = None
        self.previous_widget = None  # ✅ Added to avoid AttributeError

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