"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = require("vscode");
const path = require("path");
const utils_1 = require("./utils");
const crypto_1 = require("./crypto");
const crypto_string_1 = require("./crypto_string");
let outputChannel;
let logger;
function activate(context) {
    console.log('Obscuro extension is now active!');
    // Create output channel
    outputChannel = vscode.window.createOutputChannel("Obscuro");
    context.subscriptions.push(outputChannel);
    logger = new utils_1.Logger(outputChannel);
    // Register "Obscure" command
    let obscureDisposable = vscode.commands.registerCommand('obscuro.obscure', async (uri) => {
        if (!uri) {
            vscode.window.showErrorMessage('No file or folder selected.');
            return;
        }
        await handleObscure(uri.fsPath, 'encrypt');
    });
    // Register "Reveal" command
    let revealDisposable = vscode.commands.registerCommand('obscuro.reveal', async (uri) => {
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
async function handleObscure(targetPath, action) {
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
            }
            else {
                await performDecryption(targetPath, password);
            }
            vscode.window.showInformationMessage(`Obscuro: ${action}ion successful!`);
        }
        catch (err) {
            vscode.window.showErrorMessage(`Obscuro failed: ${err.message}`);
            logger.log(`Error: ${err.message}`);
            logger.show();
        }
    });
}
async function performEncryption(targetPath, password) {
    // Directly encrypt the file/folder without any special Python handling
    await (0, crypto_1.encryptFile)(targetPath, targetPath, password, logger);
}
async function performDecryption(targetPath, password) {
    await (0, crypto_1.decryptFile)(targetPath, password, logger);
}
async function handleSelectionObscure(action) {
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
        let result;
        if (action === 'encrypt') {
            result = await (0, crypto_string_1.encryptString)(text, password);
        }
        else {
            result = await (0, crypto_string_1.decryptString)(text, password);
        }
        await editor.edit(editBuilder => {
            editBuilder.replace(selection, result);
        });
    }
    catch (err) {
        vscode.window.showErrorMessage(`Obscuro Selection failed: ${err.message}`);
    }
}
function deactivate() { }
//# sourceMappingURL=extension.js.map