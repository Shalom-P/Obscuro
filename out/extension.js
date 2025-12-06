"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = require("vscode");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const tar = require("tar");
let outputChannel;
function activate(context) {
    console.log('Obscuro extension is now active!');
    // Create output channel
    outputChannel = vscode.window.createOutputChannel("Obscuro");
    context.subscriptions.push(outputChannel);
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
                await encryptTarget(targetPath, password);
            }
            else {
                await decryptTarget(targetPath, password);
            }
            vscode.window.showInformationMessage(`Obscuro: ${action}ion successful!`);
        }
        catch (err) {
            vscode.window.showErrorMessage(`Obscuro failed: ${err.message}`);
            outputChannel.appendLine(`Error: ${err.message}`);
            outputChannel.show();
        }
    });
}
async function encryptTarget(targetPath, password) {
    const log = (msg) => {
        outputChannel.appendLine(`[${new Date().toISOString()}] ${msg}`);
    };
    log(`Starting encryption for ${targetPath}`);
    outputChannel.show(); // Bring to front
    let fileToEncrypt = targetPath;
    let tempDir = null;
    let isPythonBinary = false;
    // Check if it's a python file
    if (fs.statSync(targetPath).isFile() && path.extname(targetPath).toLowerCase() === '.py') {
        try {
            // Helper to check for venv in a directory
            const getVenvBinDir = (dir) => {
                const venvNames = ['.venv', 'venv', 'env'];
                for (const venvName of venvNames) {
                    const venvDir = path.join(dir, venvName);
                    if (!fs.existsSync(venvDir))
                        continue;
                    const binDirLinux = path.join(venvDir, 'bin');
                    const binDirWin = path.join(venvDir, 'Scripts');
                    if (fs.existsSync(binDirLinux))
                        return binDirLinux;
                    if (fs.existsSync(binDirWin))
                        return binDirWin;
                }
                return null;
            };
            // Find nearest venv
            let venvBinDir = null;
            // 1. Check workspace folder
            const workspaceFolder = vscode.workspace.getWorkspaceFolder(vscode.Uri.file(targetPath));
            if (workspaceFolder) {
                venvBinDir = getVenvBinDir(workspaceFolder.uri.fsPath);
            }
            // 2. Walk up if not found
            if (!venvBinDir) {
                let currentDir = path.dirname(targetPath);
                const root = path.parse(currentDir).root;
                let levels = 0;
                while (currentDir !== root && levels < 10) {
                    if (workspaceFolder && currentDir === workspaceFolder.uri.fsPath) {
                        currentDir = path.dirname(currentDir);
                        levels++;
                        continue;
                    }
                    venvBinDir = getVenvBinDir(currentDir);
                    if (venvBinDir)
                        break;
                    currentDir = path.dirname(currentDir);
                    levels++;
                }
            }
            // --- Try Cython ---
            let cythonSuccess = false;
            try {
                // Determine Python executable
                let pythonCmd = 'python3';
                if (process.platform === 'win32') {
                    pythonCmd = 'python';
                }
                if (venvBinDir) {
                    const venvPythonLinux = path.join(venvBinDir, 'python');
                    const venvPythonWin = path.join(venvBinDir, 'python.exe');
                    if (fs.existsSync(venvPythonLinux))
                        pythonCmd = venvPythonLinux;
                    else if (fs.existsSync(venvPythonWin))
                        pythonCmd = venvPythonWin;
                }
                // Check if Cython and setuptools are installed
                let dependenciesInstalled = false;
                try {
                    await new Promise((resolve, reject) => {
                        Promise.resolve().then(() => require('child_process')).then(cp => {
                            // Check both Cython and setuptools.setup
                            cp.exec(`"${pythonCmd}" -c "import Cython; from setuptools import setup"`, (err) => {
                                if (err)
                                    reject(err);
                                else
                                    resolve(true);
                            });
                        });
                    });
                    dependenciesInstalled = true;
                }
                catch (e) { /* ignore */ }
                // If dependencies not found, ask to install
                if (!dependenciesInstalled) {
                    const answer = await vscode.window.showInformationMessage("Cython and setuptools are required to create importable binaries. Install them now?", "Yes", "No");
                    if (answer === "Yes") {
                        await vscode.window.withProgress({
                            location: vscode.ProgressLocation.Notification,
                            title: "Installing Cython and setuptools...",
                            cancellable: false
                        }, async () => {
                            await new Promise((resolve, reject) => {
                                Promise.resolve().then(() => require('child_process')).then(cp => {
                                    // Try to install Cython and setuptools
                                    // Handle PEP 668: If global pip fails, we might need --break-system-packages
                                    // But that's risky. Better to just try standard install, and if it fails, warn user.
                                    // Actually, let's try to detect if we are in a venv.
                                    // If not in venv, and on Linux, we might need --break-system-packages.
                                    let installCmd = `"${pythonCmd}" -m pip install cython setuptools`;
                                    // Check if we are likely in a managed environment (Linux + no venv)
                                    if (process.platform === 'linux' && !venvBinDir) {
                                        // We can try to append --break-system-packages if the first attempt fails?
                                        // Or just add it if we are bold.
                                        // Let's try standard first.
                                    }
                                    log(`Installing dependencies: ${installCmd}`);
                                    cp.exec(installCmd, (err, stdout, stderr) => {
                                        if (err) {
                                            if (stderr.includes('externally-managed-environment')) {
                                                log(`PEP 668 detected. Retrying with --break-system-packages...`);
                                                const breakCmd = `${installCmd} --break-system-packages`;
                                                cp.exec(breakCmd, (err2, stdout2, stderr2) => {
                                                    if (err2) {
                                                        log(`Installation failed even with break-system-packages: ${stderr2}`);
                                                        reject(err2);
                                                    }
                                                    else {
                                                        log(`Installation success (with break-system-packages): ${stdout2}`);
                                                        resolve(true);
                                                    }
                                                });
                                            }
                                            else {
                                                log(`Installation failed: ${stderr}`);
                                                reject(err);
                                            }
                                        }
                                        else {
                                            log(`Installation success: ${stdout}`);
                                            resolve(true);
                                        }
                                    });
                                });
                            });
                        });
                        dependenciesInstalled = true;
                    }
                }
                if (dependenciesInstalled) {
                    log(`Dependencies are installed. Proceeding with compilation...`);
                    // 1. Create setup.py
                    const setupPyPath = path.join(path.dirname(targetPath), 'setup_obscuro_temp.py');
                    const targetBasename = path.basename(targetPath);
                    const setupPyContent = `
from setuptools import setup
from Cython.Build import cythonize

setup(
    ext_modules = cythonize("${targetBasename}", compiler_directives={'language_level': "3"})
)
`;
                    fs.writeFileSync(setupPyPath, setupPyContent);
                    log(`Created temporary setup file: ${setupPyPath}`);
                    // 2. Run build command
                    try {
                        await new Promise((resolve, reject) => {
                            Promise.resolve().then(() => require('child_process')).then(cp => {
                                const buildCmd = `"${pythonCmd}" "${setupPyPath}" build_ext --inplace`;
                                log(`Running build: ${buildCmd}`);
                                cp.exec(buildCmd, { cwd: path.dirname(targetPath) }, (err, stdout, stderr) => {
                                    if (err) {
                                        log(`Build failed: ${stderr}`);
                                        reject(err);
                                    }
                                    else {
                                        log(`Build success: ${stdout}`);
                                        resolve(true);
                                    }
                                });
                            });
                        });
                        // 4. Find and rename the binary
                        const dir = path.dirname(targetPath);
                        const baseName = path.basename(targetPath, '.py');
                        const files = fs.readdirSync(dir);
                        // Look for logic.cpython-3x-....so or logic.pyd
                        const compiledFile = files.find(f => f.startsWith(baseName) && (f.endsWith('.so') || f.endsWith('.pyd')) && f !== path.basename(targetPath));
                        if (compiledFile) {
                            const compiledPath = path.join(dir, compiledFile);
                            const extension = path.extname(compiledFile); // .so or .pyd
                            const simpleExtension = compiledFile.endsWith('.pyd') ? '.pyd' : '.so';
                            const simpleName = baseName + simpleExtension;
                            const simplePath = path.join(dir, simpleName);
                            if (compiledPath !== simplePath) {
                                if (fs.existsSync(simplePath))
                                    fs.unlinkSync(simplePath);
                                fs.renameSync(compiledPath, simplePath);
                                log(`Renamed ${compiledFile} to ${simpleName}`);
                            }
                            else {
                                log(`Binary created: ${compiledFile}`);
                            }
                            cythonSuccess = true;
                        }
                        else {
                            log('Build ran but could not find output binary.');
                        }
                    }
                    catch (buildErr) {
                        throw buildErr;
                    }
                    finally {
                        // 3. Cleanup setup.py and build folder
                        if (fs.existsSync(setupPyPath)) {
                            fs.unlinkSync(setupPyPath);
                        }
                        const buildDir = path.join(path.dirname(targetPath), 'build');
                        if (fs.existsSync(buildDir)) {
                            fs.rmSync(buildDir, { recursive: true, force: true });
                        }
                        // Cleanup generated .c file
                        const cFile = path.join(path.dirname(targetPath), path.basename(targetPath, '.py') + '.c');
                        if (fs.existsSync(cFile)) {
                            fs.unlinkSync(cFile);
                        }
                    }
                }
            }
            catch (cythonErr) {
                log(`Cython attempt failed: ${cythonErr}`);
            }
            // --- Try PyInstaller (if Cython failed) ---
            if (!cythonSuccess) {
                log("Cython compilation failed or was skipped.");
                const selection = await vscode.window.showWarningMessage("Cython compilation failed. Do you want to fall back to PyInstaller? (WARNING: Resulting binary will NOT be importable)", "Yes, create executable", "No, abort");
                if (selection !== "Yes, create executable") {
                    throw new Error("Compilation aborted by user.");
                }
                log("Falling back to PyInstaller...");
                // Determine command to run pyinstaller
                // We try a list of candidates
                const candidates = [
                    'python3 -m PyInstaller',
                    'python -m PyInstaller',
                    'pyinstaller'
                ];
                if (venvBinDir) {
                    // Add venv candidates
                    const venvPython = path.join(venvBinDir, process.platform === 'win32' ? 'python.exe' : 'python');
                    if (fs.existsSync(venvPython)) {
                        candidates.unshift(`"${venvPython}" -m PyInstaller`);
                    }
                    const venvPyInstaller = path.join(venvBinDir, process.platform === 'win32' ? 'pyinstaller.exe' : 'pyinstaller');
                    if (fs.existsSync(venvPyInstaller)) {
                        candidates.unshift(`"${venvPyInstaller}"`);
                    }
                }
                // Deduplicate candidates
                const uniqueCandidates = [...new Set(candidates)];
                let pyInstallerCmd = null;
                let lastError = null;
                log(`PyInstaller Candidates: ${JSON.stringify(uniqueCandidates)}`);
                for (const cmd of uniqueCandidates) {
                    try {
                        log(`Trying command: ${cmd}`);
                        await new Promise((resolve, reject) => {
                            Promise.resolve().then(() => require('child_process')).then(cp => {
                                cp.exec(`${cmd} --version`, (err, stdout, stderr) => {
                                    if (err) {
                                        log(`Command failed: ${cmd}. Error: ${err.message}. Stderr: ${stderr}`);
                                        reject(err);
                                    }
                                    else {
                                        log(`Command success: ${cmd}. Output: ${stdout.trim()}`);
                                        resolve(true);
                                    }
                                });
                            });
                        });
                        pyInstallerCmd = cmd;
                        break; // Found a working command
                    }
                    catch (e) {
                        lastError = e;
                    }
                }
                if (!pyInstallerCmd) {
                    const msg = `Could not find PyInstaller. Candidates tried: ${JSON.stringify(uniqueCandidates)}. Last error: ${lastError}`;
                    log(msg);
                    throw new Error(msg);
                }
                // Create temp dir for build
                tempDir = fs.mkdtempSync(path.join(path.dirname(targetPath), 'obscuro_build_'));
                log(`Temp dir: ${tempDir}`);
                // Compile
                await new Promise((resolve, reject) => {
                    Promise.resolve().then(() => require('child_process')).then(cp => {
                        // --onefile: create single binary
                        // --distpath: where to put the binary
                        // --workpath: where to put build files (we'll delete this)
                        // --specpath: where to put spec file (we'll delete this)
                        const cmd = `${pyInstallerCmd} --onefile --distpath "${tempDir}" --workpath "${tempDir}/build" --specpath "${tempDir}" "${targetPath}"`;
                        log(`Compiling with: ${cmd}`);
                        cp.exec(cmd, (err, stdout, stderr) => {
                            if (err) {
                                log(`Compilation failed: ${stderr}`);
                                reject(err);
                            }
                            else {
                                log(`Compilation success`);
                                resolve(true);
                            }
                        });
                    });
                });
                // Find the binary
                // On Linux/Mac it has no extension, on Windows it has .exe
                // We assume Linux based on user info, but let's look for the file in distpath
                const baseName = path.basename(targetPath, '.py');
                const binaryPath = path.join(tempDir, baseName);
                if (fs.existsSync(binaryPath)) {
                    // Move binary to source dir
                    const destPath = path.join(path.dirname(targetPath), path.basename(binaryPath));
                    if (fs.existsSync(destPath)) {
                        fs.unlinkSync(destPath);
                    }
                    fs.renameSync(binaryPath, destPath);
                    log(`Moved binary to ${destPath}`);
                    // We do NOT change fileToEncrypt, so we encrypt the source file.
                    // WAIT: The previous logic was: "We do NOT change fileToEncrypt, so we encrypt the source file."
                    // But the user complained about "Python Binary Creation Issue" in previous turns.
                    // And the user wants "functions and classes defined in this binary is still usable outside".
                    // This implies they prefer the Cython path.
                    // If Cython fails, we fall back to PyInstaller (which won't satisfy the requirement fully, but it's a fallback).
                    // However, the previous code for PyInstaller said: "We do NOT change fileToEncrypt, so we encrypt the source file."
                    // That means the binary was left unencrypted? Or deleted?
                    // Ah, looking at previous code:
                    // It moved binary to destPath.
                    // Then it encrypted `fileToEncrypt` which was `targetPath` (the .py file).
                    // Then it deleted `targetPath`.
                    // So it left the binary (unencrypted) and the encrypted source?
                    // That seems weird. Why encrypt the source if we have the binary?
                    // Maybe to restore it later?
                    // If I use Cython, I want to encrypt the `.so` file.
                    // So I set `fileToEncrypt = compiledFile`.
                    // Then the tarball will contain the `.so` file.
                    // Then we encrypt the tarball.
                    // Then we delete `targetPath` (.py) AND `fileToEncrypt` (.so).
                }
                else if (fs.existsSync(binaryPath + '.exe')) {
                    const destPath = path.join(path.dirname(targetPath), path.basename(binaryPath + '.exe'));
                    if (fs.existsSync(destPath)) {
                        fs.unlinkSync(destPath);
                    }
                    fs.renameSync(binaryPath + '.exe', destPath);
                    log(`Moved binary to ${destPath}`);
                }
                else {
                    log(`Binary not found at ${binaryPath}`);
                    throw new Error('Binary not found after compilation');
                }
            }
        }
        catch (e) {
            vscode.window.showWarningMessage(`Python compilation failed, falling back to source encryption: ${e}`);
            // Fallback to normal encryption of the source file
        }
    }
    // 1. Create tarball in memory
    // Note: For very large folders, streams would be better, but buffering is simpler for now.
    // We will use a temporary file for the tarball to avoid memory issues with large files.
    const tempTarPath = path.join(path.dirname(targetPath), `.temp_${Date.now()}.tar`);
    try {
        await tar.c({
            file: tempTarPath,
            cwd: path.dirname(fileToEncrypt),
        }, [path.basename(fileToEncrypt)]);
        const tarBuffer = await fs.promises.readFile(tempTarPath);
        // 2. Encrypt
        const salt = crypto.randomBytes(16);
        const iv = crypto.randomBytes(12); // GCM standard IV size
        const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const encrypted = Buffer.concat([cipher.update(tarBuffer), cipher.final()]);
        const tag = cipher.getAuthTag();
        // Format: Salt(16) + IV(12) + Tag(16) + EncryptedData
        const outputFilename = `${targetPath}.obscuro`; // Keep original name + .obscuro
        const outputBuffer = Buffer.concat([salt, iv, tag, encrypted]);
        await fs.promises.writeFile(outputFilename, outputBuffer);
        // 3. Cleanup
        await fs.promises.unlink(tempTarPath);
        // Secure delete original
        if (fs.existsSync(targetPath)) {
            if (fs.statSync(targetPath).isDirectory()) {
                fs.rmSync(targetPath, { recursive: true, force: true });
            }
            else {
                fs.unlinkSync(targetPath);
            }
        }
        // If we encrypted a different file (e.g. compiled binary), delete it too
        if (fileToEncrypt !== targetPath && fs.existsSync(fileToEncrypt)) {
            fs.unlinkSync(fileToEncrypt);
        }
        // If we compiled, we also need to clean up the temp build dir
        if (tempDir) {
            fs.rmSync(tempDir, { recursive: true, force: true });
        }
    }
    catch (e) {
        // Cleanup temp file if exists
        if (fs.existsSync(tempTarPath)) {
            fs.unlinkSync(tempTarPath);
        }
        if (tempDir && fs.existsSync(tempDir)) {
            fs.rmSync(tempDir, { recursive: true, force: true });
        }
        throw e;
    }
}
async function decryptTarget(filePath, password) {
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
        // Remove binary if it exists (for Python files)
        const originalPath = filePath.replace('.obscuro', '');
        if (path.extname(originalPath) === '.py') {
            const binaryName = path.basename(originalPath, '.py');
            const dir = path.dirname(originalPath);
            // Remove PyInstaller binary
            const binaryPath = path.join(dir, binaryName);
            if (fs.existsSync(binaryPath)) {
                fs.unlinkSync(binaryPath);
            }
            if (fs.existsSync(binaryPath + '.exe')) {
                fs.unlinkSync(binaryPath + '.exe');
            }
            // Remove Cython binary (.so or .pyd or .abi3.so)
            const files = fs.readdirSync(dir);
            const compiledFiles = files.filter(f => f.startsWith(binaryName) &&
                (f.endsWith('.so') || f.endsWith('.pyd') || f.endsWith('.abi3.so')) &&
                f !== path.basename(originalPath));
            for (const f of compiledFiles) {
                try {
                    fs.unlinkSync(path.join(dir, f));
                    // console.log(`Deleted compiled file: ${f}`);
                }
                catch (e) { /* ignore */ }
            }
            // Cleanup setup files if they exist (user request)
            const setupPyPath = path.join(dir, 'setup_obscuro_temp.py');
            if (fs.existsSync(setupPyPath)) {
                fs.unlinkSync(setupPyPath);
            }
            const buildDir = path.join(dir, 'build');
            if (fs.existsSync(buildDir)) {
                fs.rmSync(buildDir, { recursive: true, force: true });
            }
        }
    }
    catch (e) {
        if (fs.existsSync(tempTarPath)) {
            fs.unlinkSync(tempTarPath);
        }
        throw e;
    }
}
function deactivate() { }
//# sourceMappingURL=extension.js.map