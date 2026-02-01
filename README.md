# Obscuro: Secure Code Encryption for VS Code

Obscuro is a powerful Visual Studio Code extension designed to protect your source code and sensitive data. It offers robust file encryption and specialized handling for Python files, compiling them into binary extensions to safeguard your intellectual property.

## Key Features

- **AES-256-GCM Encryption**: Uses industry-standard encryption to ensure your files remain confidential and tamper-proof.
- **Partial Encryption**: Encrypt specific secrets, API keys, or sensitive strings directly within your code without locking the entire file.
- **Python Binary Compilation**: Automatically compiles Python (`.py`) files into binary shared libraries (`.so` or `.pyd`) using Cython, making them importable but unreadable to humans.
- **Seamless Integration**: fast and easy-to-use commands directly from the VS Code Explorer and Editor context menus.

## Installation

1. Install the extension from the VS Code Marketplace or by dragging the `.vsix` file into the Extensions view.
2. Ensure you have **Python 3** installed if you plan to use the Python compilation features.
3. The extension will assist in installing necessary dependencies like `cython` and `setuptools`.

## Usage

### Encrypting a File
1. Right-click on any file in the VS Code Explorer.
2. Select **Obscuro: Obscure (Encrypt)**.
3. Enter a secure password and confirm it.
4. The file will be encrypted (and compiled if it's Python), and the original will be securely removed.

### Decrypting a File
1. Right-click on an `.obscuro` file.
2. Select **Obscuro: Reveal (Decrypt)**.
3. Enter the password.
4. The original file will be restored.

### Encrypting a Selection (Partial Encryption)
1. Select the text you want to encrypt in the editor (e.g., an API key).
2. Right-click and select **Obscuro: Encrypt Selection** (or run the command via Command Palette).
3. Enter a password.
4. The text will be replaced with an encrypted string format: `OBSCURO:....`.

### Decrypting a Selection
1. Select the entire encrypted string (starting `OBSCURO:`).
2. Right-click and select **Obscuro: Decrypt Selection**.
3. Enter the password.
4. The original text will be revealed.

## Security Details

- **Algorithm**: AES-256-GCM (Galois/Counter Mode).
- **Key Derivation**: PBKDF2 with SHA-256, 100,000 iterations, and a unique 16-byte salt per encryption.
- **Integrity**: GCM provides built-in integrity checking to detect tampering.
- **No Backdoors**: Passwords are never stored on disk. If you lose your password, the data cannot be recovered.

## Troubleshooting

- **"Cython compilation failed"**: Ensure `gcc` (Linux/macOS) or MSVC (Windows) is installed.
- **"Invalid format"**: Ensure you have selected the entire encrypted string including the `OBSCURO:` prefix.

---
*Created by the Obscuro Team*
