
import os
from time import sleep
import pyperclip
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QApplication, QStyle,
    QLabel, QLineEdit, QPushButton, QScrollArea, QFrame,
    QHeaderView, QMessageBox, QMainWindow
)
from PySide6.QtCore import Qt, QObject, Signal , QTimer,QSize
from PySide6.QtGui import QFont, QIcon, QPainter, QPixmap, QColor, QPen
from crypto import load_vault ,create_vault

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



VAULT_FILE = "vault.json"
# Window size constants
LOGIN_WINDOW_WIDTH = 250
LOGIN_WINDOW_HEIGHT = 350
VAULT_WINDOW_WIDTH = 600
VAULT_WINDOW_HEIGHT = 400

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

def clear_layout(layout):
    while layout.count():
        child = layout.takeAt(0)
        if child.widget():
            child.widget().deleteLater()
        elif child.layout():
            clear_layout(child.layout())

def find_password_for_domain(domain, key: str):
    if os.path.exists(VAULT_FILE):
        with open(VAULT_FILE, "rb") as f:
            try:
                entries = load_vault(f.read(), key)
                print(f"✅ Loaded {len(entries)} logins from '{VAULT_FILE}'")
            except Exception as e:
                print(f"❌ Failed to load vault: {e}")
                return
        for entry in entries:
            if entry.get("domain") == domain :
                return entry.get("password")
        print("the domain is not found in the vault")
        return None

def try_unlock(self, domain=None):
    self.master_key = self.key_input.text().strip()
    if not self.master_key:
        self.error_label.setText("Please enter a key.")
        return

    if not os.path.exists(VAULT_FILE):
        self.error_label.setText("No vault file found.")
        return

    try:
        with open(VAULT_FILE, "rb") as f:
            entries = load_vault(f.read(), self.master_key)
        if (self.__class__.__name__=="MainView"):
            self.bool=False
            self.show_vault_table(entries,self.main_window)
        else:
            password = find_password_for_domain(domain, self.master_key)
            if password:
                pyperclip.copy(password)
                print(f"✅ Copied password for {domain}!")
                clear_layout(self.main_layout)
                success_label = QLabel(f"✅ Password for {domain} copied to clipboard!")
                success_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                success_label.setFont(QFont("Consolas", 24, QFont.Weight.Bold))
                self.main_layout.addWidget(success_label)
                QTimer.singleShot(2000, lambda: self.main_window.setCentralWidget(MainView(self.main_window)))
            else:
                print("❌ No password found.")
                clear_layout(self.main_layout)
                error_label = QLabel(f"❌ No password found for {domain}.")
                error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                error_label.setFont(QFont("Consolas", 24, QFont.Weight.Bold))
                self.main_layout.addWidget(error_label)
                QTimer.singleShot(2000, lambda: self.main_window.setCentralWidget(MainView(self.main_window)))

                
    except Exception:
        self.error_label.setText("Wrong key. Try again.")
        self.key_input.clear()
        self.key_input.setFocus()

def new_login(self):
    domain = self.domain_input.text().strip()
    username = self.username_input.text().strip() == None
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
        vault_bytes = create_vault(self.master_key, self.entries)
        with open(VAULT_FILE, "wb") as f:
            f.write(vault_bytes)
            print("✅ Login saved!")
    except Exception as e:
        print(f"❌ Save failed: {e}")
    self.bool=False
    self.show_vault_table(self.entries,self.main_window)


    

class MainView(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(4, 4, 4, 4)
        self.main_layout.setSpacing(15)
        self.show_login_screen()
        self.bool=False


    def show_login_screen(self):
        clear_layout(self.main_layout)
        self.main_window.resize(LOGIN_WINDOW_WIDTH, LOGIN_WINDOW_HEIGHT)
        self.main_layout.addSpacing(20)
        title = QLabel("Password Manager")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Consolas", 20, QFont.Weight.Bold))
        self.main_layout.addWidget(title)
        self.sec_layout = QVBoxLayout()
        self.sec_layout.setContentsMargins(30, 30, 30, 15)
        self.sec_layout.setSpacing(15)

        key_label = QLabel("Enter Master Key:")
        key_label.setFont(QFont("Consolas", 12))
        self.sec_layout.addWidget(key_label)

        self.key_input = QLineEdit()
        self.key_input.setEchoMode(QLineEdit.EchoMode.PasswordEchoOnEdit)
        self.key_input.setPlaceholderText("Master key...")
        self.key_input.setFont(QFont("Consolas", 12))
        self.key_input.returnPressed.connect(lambda: try_unlock(self))
        self.sec_layout.addWidget(self.key_input)

        unlock_btn = QPushButton("Unlock")
        unlock_btn.setFont(QFont("Consolas", 12))
        unlock_btn.clicked.connect(lambda: try_unlock(self))
        self.sec_layout.addWidget(unlock_btn)

        self.error_label = QLabel("")
        self.error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.error_label.setStyleSheet("color: #FF3333;")
        self.error_label.setFont(QFont("Consolas", 12))
        self.sec_layout.addWidget(self.error_label)

        self.sec_layout.addStretch()
        hotkey_label = QLabel("Press Ctrl+Alt+P to quickly access vault") 
        hotkey_label.setFont(QFont("Consolas", 12))
        hotkey_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hotkey_label.setWordWrap(True)
        self.sec_layout.addWidget(hotkey_label)
        self.main_layout.addLayout(self.sec_layout)

    def show_vault_table(self, entries, main_window):
        self.entries = entries
        clear_layout(self.main_layout)
        main_window.resize(VAULT_WINDOW_WIDTH, VAULT_WINDOW_HEIGHT)
        self.main_layout.addSpacing(10)
        subtitle_layout = QHBoxLayout()
        back_btn = QPushButton()
        back_btn.setIcon(QApplication.style().standardIcon(QStyle.StandardPixmap.SP_ArrowBack))
        back_btn.setStyleSheet("color: #FFFFFF; background-color: #00FF00;")
        back_btn.setIconSize(QSize(24, 24))
        back_btn.setFixedSize(30, 30)
        back_btn.clicked.connect(self.show_login_screen)
        back_btn.setToolTip("Back to unlock screen")
        subtitle_layout.addWidget(back_btn)

        subtitle = QLabel(f"{len(entries)} saved logins")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setFont(QFont("Consolas", 12))
        subtitle_layout.addWidget(subtitle)

        self.main_layout.addLayout(subtitle_layout)

        self.main_layout.addSpacing(10)

        # Scrollable entry rows
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet("QScrollArea { border: none; }")
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        scroll_layout.setContentsMargins(0, 0, 0, 0)
        scroll_layout.setSpacing(0)

        for i, entry in enumerate(entries):
            row_layout = QHBoxLayout()
            row_layout.setContentsMargins(8, 6, 8, 6)
            row_layout.setSpacing(10)

            domain_label = QLabel(entry.get("domain", ""))
            domain_label.setFont(QFont("Consolas", 11))
            row_layout.addWidget(domain_label)

            username_label = QLabel(entry.get("username", ""))
            username_label.setFont(QFont("Consolas", 11))
            row_layout.addWidget(username_label)

            password_label = QLabel(entry.get("password", ""))
            password_label.setFont(QFont("Consolas", 11))
            row_layout.addWidget(password_label)

            edit_btn = QPushButton()
            edit_btn.setIcon(make_icon("\u270E", "#00FF00"))
            edit_btn.setIconSize(QSize(20, 20))
            edit_btn.setToolTip("Edit")
            edit_btn.setFixedSize(28, 28)
            edit_btn.setStyleSheet("border: 1px solid #00FF00; background-color: #002200; border-radius: 4px;")
            edit_btn.clicked.connect(lambda checked, idx=i: self.edit_entry(idx))
            row_layout.addWidget(edit_btn)

            remove_btn = QPushButton()
            remove_btn.setIcon(make_icon("\u2716", "#FF3333"))
            remove_btn.setIconSize(QSize(20, 20))
            remove_btn.setToolTip("Remove")
            remove_btn.setFixedSize(28, 28)
            remove_btn.setStyleSheet("border: 1px solid #FF3333; background-color: #220000; border-radius: 4px;")
            remove_btn.clicked.connect(lambda checked, idx=i: self.remove_entry(idx))
            row_layout.addWidget(remove_btn)

            scroll_layout.addLayout(row_layout)

            # Divider line between entries
            if i < len(entries) - 1:
                line = QFrame()
                line.setFrameShape(QFrame.Shape.HLine)
                line.setStyleSheet("background-color: #00FF00;")
                line.setFixedHeight(2)
                scroll_layout.addWidget(line)

        scroll_layout.addStretch()
        scroll_area.setWidget(scroll_widget)
        self.main_layout.addWidget(scroll_area)
        if not self.bool:
            lock_btn = QPushButton("add new login")
            lock_btn.setFont(QFont("Consolas", 14))
            lock_btn.clicked.connect(lambda: self.changeboolrebuild())
            self.main_layout.addWidget(lock_btn)
        else:
            new_login_layout = QHBoxLayout()
            self.domain_input = QLineEdit()
            self.domain_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.domain_input.setPlaceholderText("Domain")
            self.domain_input.setFont(QFont("Consolas", 12))
            new_login_layout.addWidget(self.domain_input)

            self.username_input = QLineEdit()
            self.username_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.username_input.setPlaceholderText("Username")
            self.username_input.setFont(QFont("Consolas", 12))
            new_login_layout.addWidget(self.username_input)

            self.key_input = QLineEdit()
            self.key_input.setEchoMode(QLineEdit.EchoMode.PasswordEchoOnEdit)
            self.key_input.setPlaceholderText("Password")
            self.key_input.setFont(QFont("Consolas", 12))
            new_login_layout.addWidget(self.key_input)

            add_btn = QPushButton("Add Login")
            add_btn.setFont(QFont("Consolas", 12))
            add_btn.clicked.connect(lambda: new_login(self))
            new_login_layout.addWidget(add_btn)

            self.main_layout.addLayout(new_login_layout)
    def changeboolrebuild(self):       
        self.bool=True
        self.show_vault_table(self.entries,self.main_window)

    def edit_entry(self, index):
        entry = self.entries[index]
        self.bool = False
        clear_layout(self.main_layout)
        self.main_window.resize(VAULT_WINDOW_WIDTH, VAULT_WINDOW_HEIGHT)

        title = QLabel(f"Editing: {entry.get('domain', '')}")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Consolas", 16, QFont.Weight.Bold))
        self.main_layout.addWidget(title)
        self.main_layout.addSpacing(15)

        form_layout = QVBoxLayout()
        form_layout.setContentsMargins(30, 10, 30, 10)
        form_layout.setSpacing(10)

        domain_label = QLabel("Domain:")
        domain_label.setFont(QFont("Consolas", 12))
        form_layout.addWidget(domain_label)
        self.edit_domain = QLineEdit(entry.get("domain", ""))
        self.edit_domain.setFont(QFont("Consolas", 12))
        form_layout.addWidget(self.edit_domain)

        username_label = QLabel("Username:")
        username_label.setFont(QFont("Consolas", 12))
        form_layout.addWidget(username_label)
        self.edit_username = QLineEdit(entry.get("username", ""))
        self.edit_username.setFont(QFont("Consolas", 12))
        form_layout.addWidget(self.edit_username)

        password_label = QLabel("Password:")
        password_label.setFont(QFont("Consolas", 12))
        form_layout.addWidget(password_label)
        self.edit_password = QLineEdit(entry.get("password", ""))
        self.edit_password.setFont(QFont("Consolas", 12))
        form_layout.addWidget(self.edit_password)

        self.main_layout.addLayout(form_layout)
        self.main_layout.addSpacing(10)

        btn_layout = QHBoxLayout()
        save_btn = QPushButton("Save")
        save_btn.setFont(QFont("Consolas", 12))
        save_btn.clicked.connect(lambda: self.save_edit(index))
        btn_layout.addWidget(save_btn)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setFont(QFont("Consolas", 12))
        cancel_btn.clicked.connect(lambda: self.show_vault_table(self.entries, self.main_window))
        btn_layout.addWidget(cancel_btn)
        self.main_layout.addLayout(btn_layout)

        self.error_label = QLabel("")
        self.error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.error_label.setStyleSheet("color: #FF3333;")
        self.error_label.setFont(QFont("Consolas", 12))
        self.main_layout.addWidget(self.error_label)
        self.main_layout.addStretch()

    def save_edit(self, index):
        domain = self.edit_domain.text().strip()
        username = self.edit_username.text().strip()
        password = self.edit_password.text().strip()
        if not domain or not password:
            self.error_label.setText("Domain and password are required.")
            return
        self.entries[index] = {
            "domain": domain,
            "username": username if username else "--non added--",
            "password": password
        }
        try:
            vault_bytes = create_vault(self.master_key, self.entries)
            with open(VAULT_FILE, "wb") as f:
                f.write(vault_bytes)
            print("✅ Entry updated!")
        except Exception as e:
            print(f"❌ Save failed: {e}")
        self.show_vault_table(self.entries, self.main_window)

    def remove_entry(self, index):
        entry = self.entries[index]
        reply = QMessageBox.question(
            self, "Confirm Remove",
            f"Remove login for '{entry.get('domain', '')}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.entries.pop(index)
            try:
                vault_bytes = create_vault(self.master_key, self.entries)
                with open(VAULT_FILE, "wb") as f:
                    f.write(vault_bytes)
                print("✅ Entry removed!")
            except Exception as e:
                print(f"❌ Save failed: {e}")
            self.show_vault_table(self.entries, self.main_window)
        






class hotkeyview(QWidget):
    def __init__(self,domain,main_window):
        super().__init__()
        self.domain = domain
        self.main_window = main_window
        self.main_window.resize(LOGIN_WINDOW_WIDTH, LOGIN_WINDOW_HEIGHT)
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(30, 30, 30, 30)
        self.main_layout.setSpacing(15)
        self.show_login_screen()

    def show_login_screen(self):
        clear_layout(self.main_layout)
        title = QLabel(f"Getting the password for {self.domain}")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Consolas", 24, QFont.Weight.Bold))
        self.main_layout.addWidget(title)

        self.main_layout.addSpacing(20)

        key_label = QLabel("Enter Master Key:")
        key_label.setFont(QFont("Consolas", 14))
        self.main_layout.addWidget(key_label)

        self.key_input = QLineEdit()
        self.key_input.setEchoMode(QLineEdit.EchoMode.PasswordEchoOnEdit)
        self.key_input.setPlaceholderText("Master key...")
        self.key_input.setFont(QFont("Consolas", 14))
        self.main_layout.addWidget(self.key_input)

        unlock_btn = QPushButton("Unlock")
        unlock_btn.setFont(QFont("Consolas", 14))
        unlock_btn.clicked.connect(lambda: try_unlock(self, self.domain))
        self.main_layout.addWidget(unlock_btn)

        self.error_label = QLabel("")
        self.error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.error_label.setStyleSheet("color: #FF3333;")
        self.error_label.setFont(QFont("Consolas", 12))
        self.main_layout.addWidget(self.error_label)

        self.main_layout.addStretch() 