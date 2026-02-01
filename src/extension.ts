import * as vscode from 'vscode';
import * as path from 'path';
import { Logger } from './utils';
import { encryptFile, decryptFile } from './crypto';
import { encryptString, decryptString } from './crypto_string';

let outputChannel: vscode.OutputChannel;
let logger: Logger;

export function activate(context: vscode.ExtensionContext) {
    console.log('Obscuro extension is now active!');

    // Create output channel
    outputChannel = vscode.window.createOutputChannel("Obscuro");
    context.subscriptions.push(outputChannel);
    logger = new Logger(outputChannel);

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

    // Register "Encrypt Selection" command
    let encryptSelectionDisposable = vscode.commands.registerCommand('obscuro.encryptSelection', async () => {
        await handleSelectionObscure('encrypt');
    });

    // Register "Decrypt Selection" command
    let decryptSelectionDisposable = vscode.commands.registerCommand('obscuro.decryptSelection', async () => {
        await handleSelectionObscure('decrypt');
    });

    context.subscriptions.push(encryptSelectionDisposable);
    context.subscriptions.push(decryptSelectionDisposable);
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
                await performEncryption(targetPath, password);
            } else {
                await performDecryption(targetPath, password);
            }
            vscode.window.showInformationMessage(`Obscuro: ${action}ion successful!`);
        } catch (err: any) {
            vscode.window.showErrorMessage(`Obscuro failed: ${err.message}`);
            logger.log(`Error: ${err.message}`);
            logger.show();
        }
    });
}

async function performEncryption(targetPath: string, password: string) {
    // Directly encrypt the file/folder without any special Python handling
    await encryptFile(targetPath, targetPath, password, logger);
}

async function performDecryption(targetPath: string, password: string) {
    await decryptFile(targetPath, password, logger);
}

async function handleSelectionObscure(action: 'encrypt' | 'decrypt') {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showErrorMessage('No active text editor.');
        return;
    }

    const selection = editor.selection;
    if (selection.isEmpty) {
        vscode.window.showErrorMessage('No text selected.');
        return;
    }

    const text = editor.document.getText(selection);

    const password = await vscode.window.showInputBox({
        prompt: `Enter password to ${action} selection`,
        password: true,
        ignoreFocusOut: true
    });

    if (!password) {
        return;
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

    try {
        let result: string;
        if (action === 'encrypt') {
            result = await encryptString(text, password);
        } else {
            result = await decryptString(text, password);
        }

        await editor.edit(editBuilder => {
            editBuilder.replace(selection, result);
        });

    } catch (err: any) {
        vscode.window.showErrorMessage(`Obscuro Selection failed: ${err.message}`);
    }
}
export function deactivate() { }
