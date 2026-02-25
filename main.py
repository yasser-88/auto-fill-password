
import sys
import os
import threading
from PySide6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton
from PySide6.QtCore import QObject, Signal, Slot
from PySide6.QtGui import QIcon
from pynput import keyboard
import pyperclip
from urllib.parse import urlparse as urllib_parse
from crypto import load_vault
from widgets import MainView, hotkeyview
from helpers import STYLESHEET, LOGIN_WINDOW_WIDTH, LOGIN_WINDOW_HEIGHT
import ctypes
import pystray
from PIL import Image

if sys.platform == "win32":
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("passwordmanager.app.1")

def get_domain_from_clipboard():
    url = pyperclip.paste().strip()

    if url.startswith(("http://", "https://")):
        return urllib_parse(url).netloc
    elif url:
        domain = url.split('/')[0] 
        domain = domain.split('?')[0]
        return domain if domain else None
    return None


class HotkeyEmitter(QObject):
    domain_detected = Signal(str)
    restore_requested = Signal()
    quit_requested = Signal()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.emitter = HotkeyEmitter()
        self.emitter.domain_detected.connect(self.show_unlock_popup)
        self.emitter.restore_requested.connect(self._do_restore)
        self.emitter.quit_requested.connect(self._do_quit)
        self.setWindowTitle("Password Manager")
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.png")
        self.setWindowIcon(QIcon(icon_path))
        self.setMinimumSize(0, 0)
        self.resize(LOGIN_WINDOW_WIDTH, LOGIN_WINDOW_HEIGHT)
        self.setCentralWidget(MainView(self)) 

        self.unlock_widget = None
        self.previous_widget = None
        self._tray_icon = None

    def minimize_to_tray(self):
        self.hide()
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.png")
        image = Image.open(icon_path)
        menu = pystray.Menu(
            pystray.MenuItem("Open", self._restore_from_tray, default=True),
            pystray.MenuItem("Quit", self._quit_from_tray),
        )
        self._tray_icon = pystray.Icon("PasswordManager", image, "Password Manager", menu)
        threading.Thread(target=self._tray_icon.run, daemon=True).start()

    def _restore_from_tray(self, icon=None, item=None):
        self.emitter.restore_requested.emit()

    def _quit_from_tray(self, icon=None, item=None):
        self.emitter.quit_requested.emit()

    @Slot()
    def _do_restore(self):
        if self._tray_icon:
            self._tray_icon.stop()
            self._tray_icon = None
        self.setCentralWidget(MainView(self))
        self.setMinimumSize(0, 0)
        self.setMaximumSize(16777215, 16777215)
        self.resize(LOGIN_WINDOW_WIDTH, LOGIN_WINDOW_HEIGHT)
        self.showNormal()
        self.activateWindow()

    @Slot()
    def _do_quit(self):
        if self._tray_icon:
            self._tray_icon.stop()
            self._tray_icon = None
        QApplication.quit()

    @Slot(str)
    def show_unlock_popup(self, domain):
        self.setCentralWidget(hotkeyview(domain, self))
        
def start_hotkey_listener(emitter):
    def on_activate():
        domain = get_domain_from_clipboard()
        if domain:
            emitter.domain_detected.emit(domain)

    with keyboard.GlobalHotKeys({'<ctrl>+<alt>+p': on_activate}) as h:
        h.join()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    app.setStyleSheet(STYLESHEET)
    window = MainWindow()
    window.show()
    
    emitter = window.emitter
    threading.Thread(
        target=start_hotkey_listener,
        args=(emitter,),
        daemon=True
    ).start()
    
    sys.exit(app.exec())