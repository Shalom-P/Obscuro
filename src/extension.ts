import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import * as crypto from 'crypto';
import * as tar from 'tar';

export function activate(context: vscode.ExtensionContext) {
    console.log('Obscuro extension is now active!');

    // Register "Obscure" command
    let obscureDisposable = vscode.commands.registerCommand('obscuro.obscure', async (uri: vscode.Uri) => {
        if (!uri) {
            vscode.window.showErrorMessage('No file or folder selected.');
            return;
        }
        await handleObscure(uri.fsPath, 'encrypt');
    });

    // Register "Reveal" command
    let revealDisposable = vscode.commands.registerCommand('obscuro.reveal', async (uri: vscode.Uri) => {
        if (!uri) {
            vscode.window.showErrorMessage('No file selected.');
            return;
        }
        await handleObscure(uri.fsPath, 'decrypt');
    });

    context.subscriptions.push(obscureDisposable);
    context.subscriptions.push(revealDisposable);
}

async function handleObscure(targetPath: string, action: 'encrypt' | 'decrypt') {
    const password = await vscode.window.showInputBox({
        prompt: `Enter password to ${action} '${path.basename(targetPath)}'`,
        password: true,
        ignoreFocusOut: true
    });

    if (!password) {
        return; // User cancelled
    }

    if (action === 'encrypt') {
        const confirm = await vscode.window.showInputBox({
            prompt: "Confirm password",
            password: true,
            ignoreFocusOut: true
        });
        if (password !== confirm) {
            vscode.window.showErrorMessage("Passwords do not match!");
            return;
        }
    }

    vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: `Obscuro: ${action === 'encrypt' ? 'Encrypting' : 'Decrypting'}...`,
        cancellable: false
    }, async (progress) => {
        try {
            if (action === 'encrypt') {
                await encryptTarget(targetPath, password);
            } else {
                await decryptTarget(targetPath, password);
            }
            vscode.window.showInformationMessage(`Obscuro: ${action}ion successful!`);
        } catch (err: any) {
            vscode.window.showErrorMessage(`Obscuro failed: ${err.message}`);
        }
    });
}

async function encryptTarget(targetPath: string, password: string) {
    // 1. Create tarball in memory
    // Note: For very large folders, streams would be better, but buffering is simpler for now.
    // We will use a temporary file for the tarball to avoid memory issues with large files.
    const tempTarPath = path.join(path.dirname(targetPath), `.temp_${Date.now()}.tar`);

    try {
        await tar.c({
            file: tempTarPath,
            cwd: path.dirname(targetPath),
        }, [path.basename(targetPath)]);

        const tarBuffer = await fs.promises.readFile(tempTarPath);

        // 2. Encrypt
        const salt = crypto.randomBytes(16);
        const iv = crypto.randomBytes(12); // GCM standard IV size
        const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');

        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const encrypted = Buffer.concat([cipher.update(tarBuffer), cipher.final()]);
        const tag = cipher.getAuthTag();

        // Format: Salt(16) + IV(12) + Tag(16) + EncryptedData
        const outputFilename = `${targetPath}.obscuro`;
        const outputBuffer = Buffer.concat([salt, iv, tag, encrypted]);

        await fs.promises.writeFile(outputFilename, outputBuffer);

        // 3. Cleanup
        await fs.promises.unlink(tempTarPath);

        // Secure delete original (simple unlink)
        if (fs.statSync(targetPath).isDirectory()) {
            fs.rmSync(targetPath, { recursive: true, force: true });
        } else {
            fs.unlinkSync(targetPath);
        }
    } catch (e) {
        // Cleanup temp file if exists
        if (fs.existsSync(tempTarPath)) {
            fs.unlinkSync(tempTarPath);
        }
        throw e;
    }
}

async function decryptTarget(filePath: string, password: string) {
    const fileBuffer = await fs.promises.readFile(filePath);

    // Extract parts
    // Format: Salt(16) + IV(12) + Tag(16) + EncryptedData
    if (fileBuffer.length < 44) {
        throw new Error("File is too short to be a valid Obscuro file.");
    }

    const salt = fileBuffer.subarray(0, 16);
    const iv = fileBuffer.subarray(16, 28);
    const tag = fileBuffer.subarray(28, 44);
    const encryptedData = fileBuffer.subarray(44);

    const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);

    const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);

    // Extract tarball
    const outputDir = path.dirname(filePath);
    const tempTarPath = path.join(outputDir, `.temp_decrypt_${Date.now()}.tar`);

    try {
        await fs.promises.writeFile(tempTarPath, decrypted);

        await tar.x({
            file: tempTarPath,
            cwd: outputDir
        });

        // Cleanup
        await fs.promises.unlink(tempTarPath);
        await fs.promises.unlink(filePath); // Delete encrypted file on success
    } catch (e) {
        if (fs.existsSync(tempTarPath)) {
            fs.unlinkSync(tempTarPath);
        }
        throw e;
    }
}

export function deactivate() { }
