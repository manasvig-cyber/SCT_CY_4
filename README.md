Keylogger Demo Project
This project is a safe, educational demonstration of a login GUI application in Python. It simulates a login form, records username and password data securely, and stores it in a log file with hashed and encrypted password tokens. This is designed purely for classroom or personal demonstration purposes. It does not capture system-wide keystrokes.

Project Features
The application provides a simple login window with:

Username or email field
Password field
Log In button
Upon submission, the following data is saved in logs/credentials.log:

Timestamp of login attempt
Username
Password SHA-256 hash
Encrypted password token using Fernet (cryptography library)
The project automatically creates a key.key file used for encrypting and decrypting password tokens.

Security and Ethical Notes

Do not use this project to capture other people's credentials without explicit consent. Use only your own accounts or supervised classroom scenarios.

Keep key.key private. Anyone with this file can decrypt the logged passwords.

Sensitive files (logs/credentials.log and key.key) are ignored in GitHub using .gitignore to prevent accidental exposure.

Folder Structure

KeyloggerDemo
demo_login.py Python GUI script for login
decrypt_log.py Helper script to decrypt and view logged entries
logs Folder where login entries are saved (ignored in git)
key.key Encryption key (ignored in git)
.gitignore Prevents logs and key from being uploaded

Setup Instructions

Install Python 3 if not already installed.

Install required packages using pip:

pip install pillow
pip install cryptography

Navigate to the project folder in terminal or PowerShell.

Run the demo login application:

python demo_login.py

Enter a username and password and click Log In. The log file will be automatically opened in Notepad.

To view decrypted passwords, run the helper script:

python decrypt_log.py


Remember to keep logs/credentials.log and key.key in .gitignore to prevent exposing sensitive information.
