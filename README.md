# Auto-Fill Password Manager

password manager that runs on your machine. no cloud everything stays local

## How it works

two ways to use it:
- **Desktop app** - hit Ctrl+Alt+P and it auto-types your password. copies username first then types the password. just copy the website url before using the hotkey the passwprd is copied to the clipboard
- **Chrome extension** - click the icon on login pages enter your master password and it fills the form. new sites get captured and saved automatically

encrypted with your master password using AES-GCM. vault is a JSON file in the project folder

## Setup

install dependencies:
pip install -r req.txt

run the app:
python main.py #starts the desktop app and server on localhost:5000

chrome extension:
- chrome://extensions
- turn on developer mode
- load unpacked
- pick the extension folder

## What I learned

started this to learn encryption/decryption and ended up adding new functionalites and learning throught:
- pyside6 GUI with system tray and global hotkeys
- connecting python with chrome extension through fastapi
- chrome extension structure (content/background scripts communication)
- organizing project files so theyre readable

## Files

- main.py - desktop app
- server.py - api server
- crypto.py - encryption stuff
- helpers.py - utilities
- widgets.py - gui parts
- extension/ - chrome extension
- vault.json - where credentials get stored

