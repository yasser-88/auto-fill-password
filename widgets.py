
import os
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QApplication, QStyle,
    QPushButton, QScrollArea, QFrame, QMessageBox, QMainWindow
)
from PySide6.QtCore import QTimer, QSize
from crypto import create_vault, _write_vault
from helpers import (
    VAULT_FILE, AUTO_LOCK_TIMEOUT_MS,
    LOGIN_WINDOW_WIDTH, LOGIN_WINDOW_HEIGHT,
    VAULT_WINDOW_WIDTH, VAULT_WINDOW_HEIGHT,
    make_icon, clear_layout, check_password_strength,
    try_unlock, new_login,
    make_label, make_input, make_button,
)


class MainView(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(4, 4, 4, 4)
        self.main_layout.setSpacing(15)
        self.bool=False
        self.master_key = ""

        # Hard auto-lock timer: locks vault exactly 2 minutes after unlock

        self._auto_lock_timer = QTimer(self)
        self._auto_lock_timer.setSingleShot(True)
        self._auto_lock_timer.timeout.connect(self._auto_lock)
        if  os.path.exists("vault.json"):
            self.show_login_screen()
        else:
            self.show_create_vault_screen()

    def _start_auto_lock(self):
        """Start the 2-minute hard lock countdown."""
        self._auto_lock_timer.start(AUTO_LOCK_TIMEOUT_MS)

    def _auto_lock(self):
        """Lock the vault by returning to the login screen."""
        print("\U0001f512 Vault locked (2 min expired).")
        self.main_window.setCentralWidget(MainView(self.main_window))
        


    def show_login_screen(self):
        clear_layout(self.main_layout)
        self.main_window.resize(LOGIN_WINDOW_WIDTH, LOGIN_WINDOW_HEIGHT)
        self.main_layout.addSpacing(20)
        self.main_layout.addWidget(make_label("Password Manager", size=20, bold=True, align_center=True))
        self.sec_layout = QVBoxLayout()
        self.sec_layout.setContentsMargins(30, 30, 30, 15)
        self.sec_layout.setSpacing(15)

        self.sec_layout.addWidget(make_label("Enter Master Key:"))

        self.key_input = make_input("Master key...", password=True)
        self.key_input.returnPressed.connect(lambda: try_unlock(self))
        self.sec_layout.addWidget(self.key_input)

        self.sec_layout.addWidget(make_button("Unlock", on_click=lambda: try_unlock(self)))

        self.error_label = make_label("", align_center=True, color="#FF3333")
        self.sec_layout.addWidget(self.error_label)

        self.sec_layout.addStretch()
        self.sec_layout.addWidget(make_label("Press Ctrl+Alt+P to quickly access vault", align_center=True, word_wrap=True))
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

        subtitle_layout.addWidget(make_label(f"{len(entries)} saved logins", align_center=True))

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

            row_layout.addWidget(make_label(entry.get("domain", ""), size=11))
            row_layout.addWidget(make_label(entry.get("username", ""), size=11))

            password_label = make_label("••••••••", size=11)
            row_layout.addWidget(password_label)

            # Toggle password visibility button
            show_btn = QPushButton()
            show_btn.setIcon(make_icon("👁", "#00FF00"))
            show_btn.setIconSize(QSize(20, 20))
            show_btn.setToolTip("Show/Hide")
            show_btn.setFixedSize(28, 28)
            show_btn.setStyleSheet("border: 1px solid #00FF00; background-color: #002200; border-radius: 4px;")
            actual_password = entry.get("password", "")
            show_btn.clicked.connect(lambda checked, lbl=password_label, pw=actual_password: (
                lbl.setText(pw) if lbl.text() == "••••••••" else lbl.setText("••••••••")
            ))
            row_layout.addWidget(show_btn)

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
            self.main_layout.addWidget(make_button("add new login", size=14, on_click=lambda: self.changeboolrebuild()))
        else:
            new_login_layout = QHBoxLayout()
            self.domain_input = make_input("Domain")
            new_login_layout.addWidget(self.domain_input)

            self.username_input = make_input("Username")
            new_login_layout.addWidget(self.username_input)

            self.key_input = make_input("Password", password=True)
            new_login_layout.addWidget(self.key_input)

            new_login_layout.addWidget(make_button("Add Login", on_click=lambda: new_login(self)))

            self.main_layout.addLayout(new_login_layout)

    def show_create_vault_screen(self):
        clear_layout(self.main_layout)
        self.main_window.resize(LOGIN_WINDOW_WIDTH, LOGIN_WINDOW_HEIGHT)
        self.main_layout.addSpacing(20)
        self.main_layout.addWidget(make_label("No vault found. create a new one", size=20, bold=True, align_center=True, word_wrap=True))
        self.sec_layout = QVBoxLayout()
        self.sec_layout.setContentsMargins(30, 30, 30, 15)
        self.sec_layout.setSpacing(15)

        self.sec_layout.addWidget(make_label("Enter the Master Key:"))

        self.key_input = make_input("Master key...", password=True)
        self.key_input.returnPressed.connect(lambda: self.create_vault_show_login())
        self.sec_layout.addWidget(self.key_input)

        self.sec_layout.addWidget(make_button("Unlock", on_click=lambda: self.create_vault_show_login()))

        self.error_label = make_label("remember this key, it cannot be recovered!", align_center=True, word_wrap=True, color="#FF3333")
        self.sec_layout.addWidget(self.error_label)
        self.main_layout.addLayout(self.sec_layout)

        self.sec_layout.addStretch()

    def create_vault_show_login(self):
        master_key = self.key_input.text().strip()
        if not master_key:
            self.error_label.setText("Please enter a key.")
            return
        strength_error = check_password_strength(master_key)
        if strength_error:
            self.error_label.setText(strength_error)
            return
        try:
            create_vault(master_key, [])

            print("✅ Vault created!")
            self.show_vault_table([], self.main_window)
        except Exception as e:
            print(f"❌ Vault creation failed: {e}")
            self.error_label.setText("Failed to create vault. Try again.")



    def changeboolrebuild(self):       
        self.bool=True
        self.show_vault_table(self.entries,self.main_window)

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
                _write_vault(self.master_key, self.entries)
            except Exception as e:
                print(f"❌ Save failed: {e}")
            self.show_vault_table(self.entries, self.main_window)

    def edit_entry(self, index):
        """Show the edit screen for a vault entry."""
        entry = self.entries[index]
        self.bool = False
        clear_layout(self.main_layout)
        self.main_window.resize(VAULT_WINDOW_WIDTH, VAULT_WINDOW_HEIGHT)

        self.main_layout.addWidget(make_label(
            f"Editing: {entry.get('domain', '')}", size=16, bold=True, align_center=True))
        self.main_layout.addSpacing(15)

        form_layout = QVBoxLayout()
        form_layout.setContentsMargins(30, 10, 30, 10)
        form_layout.setSpacing(10)

        form_layout.addWidget(make_label("Domain:"))
        self.edit_domain = make_input(text=entry.get("domain"))
        form_layout.addWidget(self.edit_domain)

        form_layout.addWidget(make_label("Username:"))
        self.edit_username = make_input(text=entry.get("username", ""))
        form_layout.addWidget(self.edit_username)

        form_layout.addWidget(make_label("Password:"))
        self.edit_password = make_input(text=entry.get("password"), password=True)
        form_layout.addWidget(self.edit_password)

        self.main_layout.addLayout(form_layout)
        self.main_layout.addSpacing(10)

        btn_layout = QHBoxLayout()
        btn_layout.addWidget(make_button("Save", on_click=lambda: self.save_edit(index)))
        btn_layout.addWidget(make_button("Cancel", on_click=lambda: self.show_vault_table(self.entries, self.main_window)))
        self.main_layout.addLayout(btn_layout)

        self.error_label = make_label("", align_center=True, color="#FF3333")
        self.main_layout.addWidget(self.error_label)
        self.main_layout.addStretch()

    def save_edit(self, index):
        """Save an edited vault entry."""
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
            _write_vault(self.master_key, self.entries)
        except Exception as e:
            print(f"\u274c Save failed: {e}")
        self.show_vault_table(self.entries, self.main_window)
        






class hotkeyview(QWidget):
    def __init__(self,domain,main_window):
        super().__init__(main_window)
        self.window = main_window
        self.domain = domain
        self.master_key = ""
        self.main_window = main_window
        self.main_window.resize(LOGIN_WINDOW_WIDTH+65, LOGIN_WINDOW_HEIGHT+20)
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(30, 30, 30, 30)
        self.main_layout.setSpacing(15)
        self.show_login_screen()

    def show_login_screen(self):
        clear_layout(self.main_layout)
        self.main_layout.addWidget(make_label(f"Getting the password for {self.domain}", size=24, bold=True, align_center=True,word_wrap=True))

        self.main_layout.addSpacing(20)

        self.main_layout.addWidget(make_label("Enter Master Key:", size=14))

        self.key_input = make_input("Master key...", size=14, password=True)
        self.main_layout.addWidget(self.key_input)

        self.main_layout.addWidget(make_button("Unlock", size=14, on_click=lambda: try_unlock(self, self.domain)))

        self.error_label = make_label("", align_center=True, color="#FF3333")
        self.main_layout.addWidget(self.error_label)

        self.main_layout.addStretch()

    def show_add_new_login(self,entries):
        """Show the edit screen for a new vault entry from hotkey."""
        self.entries = entries
        clear_layout(self.main_layout)

        self.main_layout.addWidget(make_label("New Login", size=16, bold=True, align_center=True))
        self.main_layout.addSpacing(7)

        form_layout = QVBoxLayout()
        form_layout.setContentsMargins(30, 10, 30, 10)
        form_layout.setSpacing(10)

        form_layout.addWidget(make_label("Domain:"))
        self.edit_domain = make_input(text=self.domain)
        form_layout.addWidget(self.edit_domain)

        form_layout.addWidget(make_label("Username:"))
        self.edit_username = make_input("username....")
        form_layout.addWidget(self.edit_username)

        form_layout.addWidget(make_label("Password:"))
        self.edit_password = make_input("password", password=True)
        form_layout.addWidget(self.edit_password)

        self.main_layout.addLayout(form_layout)
        self.main_layout.addSpacing(10)

        form_layout.addWidget(make_button("Save", on_click=lambda: self.save_edit()))
        form_layout.addWidget(make_button("Cancel", on_click=lambda: self._cancel_to_main()))
        self.main_layout.addLayout(form_layout)

        self.error_label = make_label("", align_center=True, color="#FF3333")
        self.main_layout.addWidget(self.error_label)

        # Resize AFTER all widgets are added so Qt knows the actual content size
        self.main_window.adjustSize()
        self.main_window.resize(300, max(400, self.main_window.sizeHint().height()))
        print(f"length {self.main_window.sizeHint().height()}")

    def _cancel_to_main(self):
        """Return to main view and restore the original window size."""
        view = MainView(self.main_window)
        self.main_window.setCentralWidget(view)
        self.main_window.setMinimumSize(0, 0)
        QApplication.processEvents()
        self.main_window.resize(LOGIN_WINDOW_WIDTH, LOGIN_WINDOW_HEIGHT)

    def save_edit(self):
        """Save a new vault entry from hotkey."""
        domain = self.edit_domain.text().strip()
        username = self.edit_username.text().strip()
        password = self.edit_password.text().strip()
        if not domain or not password:
            self.error_label.setText("Domain and password are required.")
            return
        self.entries.append({
            "domain": domain,
            "username": username if username else "--non added--",
            "password": password
        })
        try:
            _write_vault(self.master_key, self.entries)
        except Exception as e:
            print(f"\u274c Save failed: {e}")
        print(f"\u2705 Saved password for {domain}!")
        clear_layout(self.main_layout)
        self.main_layout.addWidget(make_label(f"\u2705 Password for {domain} is saved!", size=24, bold=True, align_center=True))
        QTimer.singleShot(2000, lambda: self.main_window.setCentralWidget(MainView(self.main_window)))