# Obscuro: Secure Code Encryption for VS Code

Obscuro is a powerful Visual Studio Code extension designed to protect your source code and sensitive data. It offers robust file and folder encryption, partial in-line encryption, and specialized handling for Python files.

## Key Features

- **AES-256-GCM Encryption**: Industry-standard encryption ensures your files and folders remain confidential and tamper-proof.
- **Folder & File Locking**: Lock entire folders or individual files with a password. Locked items are fully encrypted on disk and restored safely on unlock.
- **Partial Encryption**: Encrypt specific secrets, API keys, or sensitive strings directly within your code without locking the entire file.
- **Python Binary Compilation**: Automatically compiles Python (`.py`) files into binary shared libraries (`.so` or `.pyd`) using Cython.
- **Streaming Encryption**: Large files and folders are encrypted using streams — no memory overflow even on multi-GB folders.
- **Seamless Integration**: Commands available directly from the VS Code Explorer and Editor context menus.

## Installation

1. Install the extension from the VS Code Marketplace / Open VSX, or drag the `.vsix` file into the Extensions view.
2. Ensure you have **Python 3** installed if you plan to use the Python compilation features.

## Usage

### Locking a File or Folder
1. Right-click on any file or folder in the VS Code Explorer.
2. Select **Obscuro: Lock Item (Read-Only)** (plaintext read-only) or **Obscuro: Obscure (Encrypt)** (full encryption).
3. Enter a secure password and confirm it.
4. The item is locked/encrypted and the original is securely removed.

### Unlocking a File or Folder
1. Right-click on the locked item (`.obscuro-lock` companion or the encrypted file).
2. Select **Obscuro: Unlock Item (Writeable)** or **Obscuro: Reveal (Decrypt)**.
3. Enter the password — the original file or folder is safely restored.

### Encrypting a File
1. Right-click on any file in the VS Code Explorer.
2. Select **Obscuro: Obscure (Encrypt)**.
3. Enter a secure password and confirm it.
4. The file will be encrypted and the original securely removed.

### Decrypting a File
1. Right-click on an `.obscuro` file.
2. Select **Obscuro: Reveal (Decrypt)**.
3. Enter the password — the original file will be restored.

### Encrypting a Selection (Partial Encryption)
1. Select the text you want to encrypt in the editor (e.g., an API key).
2. Right-click and select **Obscuro: Encrypt Selection**.
3. Enter a password. The text is replaced with `OBSCURO:....`.

### Decrypting a Selection
1. Select the entire encrypted string (starting `OBSCURO:`).
2. Right-click and select **Obscuro: Decrypt Selection**.
3. Enter the password — the original text is revealed inline.

## Security Details

- **Algorithm**: AES-256-GCM (Galois/Counter Mode).
- **Key Derivation**: PBKDF2 with SHA-256, 100,000 iterations, unique 16-byte salt per encryption.
- **Integrity**: GCM provides built-in authentication — any tampering is detected before decryption.
- **Safe Unlock**: Encrypted data is only deleted from disk *after* successful decryption and extraction — your data is never lost on a failed unlock.
- **No Backdoors**: Passwords are never stored on disk. If you lose your password, the data cannot be recovered.

## Troubleshooting

- **"Cython compilation failed"**: Ensure `gcc` (Linux/macOS) or MSVC (Windows) is installed.
- **"Invalid format"**: Ensure you have selected the entire encrypted string including the `OBSCURO:` prefix.
- **"Integrity check failed"**: The file was modified externally after locking. Your encrypted backup is preserved.

## Changelog

### v2.2.9
- **Bug fix**: Encrypted file is now only removed *after* successful decryption/extraction. Previously a failed unlock (wrong password, corrupted data) could permanently delete the encrypted file.
- Temp file cleanup on any decryption failure for both file and directory paths.

### v2.2.8
- Streaming encryption/decryption for large folders (no more memory overflow on large datasets).
- Backward-compatible with legacy in-memory encrypted files.

---
*Created by the Obscuro Team*
