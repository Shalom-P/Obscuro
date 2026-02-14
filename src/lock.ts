

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as tar from 'tar';
import { exec } from 'child_process';
import { promisify } from 'util';
import { encryptData, decryptData, decryptString } from './crypto_string';
import { ILogger, LockMetadata } from './types';
import { Readable } from 'stream';

const execAsync = promisify(exec);
const VERIFICATION_TOKEN = "VERIFIED_OBSCURO_LOCK";

// Helper to stream tar to buffer
async function createTarBuffer(cwd: string, target: string): Promise<Buffer> {
    const stream = tar.c({
        cwd: cwd,
        gzip: false
    }, [target]);

    const chunks: Buffer[] = [];
    for await (const chunk of stream) {
        chunks.push(Buffer.from(chunk));
    }
    return Buffer.concat(chunks);
}

// Helper to extract tar buffer
async function extractTarBuffer(buffer: Buffer, cwd: string): Promise<void> {
    const stream = Readable.from(buffer);
    const extract = tar.x({
        cwd: cwd
    });

    return new Promise((resolve, reject) => {
        stream.pipe(extract)
            .on('finish', resolve)
            .on('error', reject);

        // Also handle errors on source stream just in case
        stream.on('error', reject);
    });
}

export async function lockFile(targetPath: string, password: string, logger: ILogger, options: { encrypt: boolean } = { encrypt: true }) {
    logger.log(`Locking (${options.encrypt ? 'Secure Encrypted' : 'Plaintext Read-Only'}): ${targetPath}`);

    const lockFilePath = `${targetPath}.obscuro-lock`;
    const targetName = path.basename(targetPath);
    const targetDir = path.dirname(targetPath);

    if (fs.existsSync(lockFilePath)) {
        throw new Error(`Item is already locked. Lock file exists: ${lockFilePath}`);
    }

    const stats = await fs.promises.stat(targetPath);
    const isDirectory = stats.isDirectory();
    let originalData: Buffer;

    // 1. Read Original Content
    if (isDirectory) {
        logger.log("  Target is a directory. Archiving...");
        // Tar the directory relative to its parent
        originalData = await createTarBuffer(targetDir, targetName);
    } else {
        originalData = await fs.promises.readFile(targetPath);
    }

    // 2. Encrypt Content (Always for backup)
    const encryptedString = await encryptData(originalData, password);

    // 3. Calculate Hash of Encrypted Content or Original Content?
    // We should hash the content on disk.
    // If plaintext lock: Hash originalData.
    // If encrypted lock: Hash encryptedString.
    let contentToHash = options.encrypt ? encryptedString : originalData.toString('utf8');
    const fileHash = crypto.createHash('sha256').update(contentToHash, 'utf8').digest('hex');

    // 4. Create Metadata Token
    const metadata: LockMetadata = {
        token: VERIFICATION_TOKEN,
        hash: fileHash,
        encryptedContent: encryptedString, // Always store backup
        isEncrypted: options.encrypt,
        isDirectory: isDirectory
    };
    const encryptedMetadata = await encryptData(JSON.stringify(metadata), password);

    // 5. Update File with Encrypted Content (If requested)
    if (options.encrypt) {
        // For directories, we must first remove the directory and replace it with a file
        if (isDirectory) {
            await fs.promises.rm(targetPath, { recursive: true, force: true });
        }
        await fs.promises.writeFile(targetPath, encryptedString, 'utf8');
    } else {
        // Plaintext Lock: Do NOT write content (it's already there).
        // But if directory, do we support Plaintext Lock?
        // Directories: "Read Only" usually means distinct files are read only?
        // Or folder itself is immutable?
        // System `chflags uchg` on folder prevents adding/removing files but not editing content of files inside.
        // For simplicity, let's say directories always encrypt if locked via Obscuro for now?
        // Or if plaintext lock for directory, we iterate and lock all files? Recursively?
        // Current architecture treats "Locked Directory" as "Archived File".
        // If we want "Plaintext Lock" for directory, we probably shouldn't archive it.
        // But logic below expects "Original Data" to be restored.

        // For now, force encrypt for directories to avoid complexity.
        if (isDirectory && !options.encrypt) {
            logger.log("  Directory detected. Forcing encryption for directory lock.");
            // Actually, ignoring options.encrypt for directories or throwing error?
            // Let's force it to true for directories for safety.
            if (isDirectory) {
                await fs.promises.rm(targetPath, { recursive: true, force: true });
                await fs.promises.writeFile(targetPath, encryptedString, 'utf8');
            }
        }
    }

    // 6. Write Metadata to Lock File
    await fs.promises.writeFile(lockFilePath, encryptedMetadata, 'utf8');

    // 7. Set Read-Only Permission (chmod a-w) & Immutable Flag (chflags uchg)
    try {
        await execAsync(`chmod a-w "${targetPath}"`);
        await execAsync(`chflags uchg "${targetPath}"`);
        logger.log(`Item locked & encrypted successfully: ${targetPath}`);
    } catch (error: any) {
        logger.log(`Failed to set flags: ${error.message}`);

        // Use basic recovery (doesn't fully restore folders perfectly on failure if rm succeeded, but better than nothing)
        // Ideally should have backup, but for now just try to write back if we can.
        // If it was directory and we removed it, we're in trouble if we crash here. 
        // But preventing write-only flag failure shouldn't lose data, just fail to lock.
        // We already wrote encrypted data. So effectively it IS locked/encrypted, just maybe not immutable.
        // So we might NOT want to revert to cleartext if encryption succeeded but chmod failed?
        // Let's stick to existing pattern: try to revert.

        try {
            await execAsync(`chmod u+w "${targetPath}"`);
            if (isDirectory) {
                await fs.promises.unlink(targetPath);
                await fs.promises.mkdir(targetPath);
                await extractTarBuffer(originalData, targetDir);
            } else {
                await fs.promises.writeFile(targetPath, originalData);
            }
        } catch (cleanupErr) {
            logger.log(`CRITICAL: Failed to revert content after flag failure: ${cleanupErr}`);
        }

        if (fs.existsSync(lockFilePath)) {
            await fs.promises.unlink(lockFilePath);
        }

        throw new Error(`Failed to set read-only flag. Lock aborted. Error: ${error.message}`);
    }
}

export async function unlockFile(targetPath: string, password: string, logger: ILogger) {
    logger.log(`Unlocking: ${targetPath}`);

    const lockFilePath = `${targetPath}.obscuro-lock`;
    const targetDir = path.dirname(targetPath);

    if (!fs.existsSync(lockFilePath)) {
        throw new Error(`No lock file found (${lockFilePath}). Cannot verify password.`);
    }

    // 1. Verify Password & Integrity
    let isDirectory = false;
    try {
        const encryptedMetadata = await fs.promises.readFile(lockFilePath, 'utf8');
        const decryptedMetadataBuffer = await decryptData(encryptedMetadata, password);
        const decryptedMetadataString = decryptedMetadataBuffer.toString('utf8');

        let metadata: LockMetadata;
        try {
            metadata = JSON.parse(decryptedMetadataString);
            isDirectory = !!metadata.isDirectory;
        } catch (e) {
            // Legacy lock file support
            if (decryptedMetadataString === VERIFICATION_TOKEN) {
                logger.log("Legacy lock file detected.");
                metadata = { token: VERIFICATION_TOKEN, hash: "" };
            } else {
                throw new Error("Invalid lock file format.");
            }
        }

        if (metadata.token !== VERIFICATION_TOKEN) {
            throw new Error("Invalid password (token mismatch).");
        }

        // Integrity Check
        if (metadata.hash) {
            const currentFileContent = await fs.promises.readFile(targetPath, 'utf8');
            const currentHash = crypto.createHash('sha256').update(currentFileContent, 'utf8').digest('hex');

            if (currentHash !== metadata.hash) {
                throw new Error("Integrity check failed! The item has been externally modified.");
            }
        }

    } catch (error: any) {
        throw error;
    }

    let metadata: LockMetadata | undefined;
    try {
        const encryptedMetadata = await fs.promises.readFile(lockFilePath, 'utf8');
        const decryptedMetadataBuffer = await decryptData(encryptedMetadata, password);
        const decryptedMetadataString = decryptedMetadataBuffer.toString('utf8');
        metadata = JSON.parse(decryptedMetadataString);
    } catch (e) {
        // Best effort to get metadata for backup content, but if we fail here, we might have failed earlier too.
        // Actually, we already parsed metadata in Step 1. We should just reuse it.
        // Refactoring to return metadata from Step 1 or lift scope.
    }

    // 2. Remove Immutable Flag & Restore Write Permission
    try {
        await execAsync(`chflags nouchg "${targetPath}"`);
        await execAsync(`chmod u+w "${targetPath}"`);
    } catch (error: any) {
        throw new Error(`Failed to remove read-only flag: ${error.message}`);
    }

    // 3. Decrypt Content
    try {
        let encryptedString: string | undefined;

        if (metadata && metadata.encryptedContent) {
            encryptedString = metadata.encryptedContent;
        } else {
            // Fallback to reading file on disk (Legacy / Missing backup)
            const isEncrypted = metadata?.isEncrypted ?? true; // Default to true for legacy
            if (isEncrypted && fs.existsSync(targetPath)) {
                encryptedString = await fs.promises.readFile(targetPath, 'utf8');
            }
        }

        const isEncrypted = metadata?.isEncrypted ?? true;

        if (isEncrypted) {
            if (encryptedString && encryptedString.startsWith("OBSCURO:")) {
                const decryptedBuffer = await decryptData(encryptedString, password);

                if (isDirectory) {
                    await fs.promises.unlink(targetPath);
                    logger.log("  Restoring directory structure...");
                    await extractTarBuffer(decryptedBuffer, targetDir);
                } else {
                    await fs.promises.writeFile(targetPath, decryptedBuffer);
                }
                logger.log(`Item decrypted and restored: ${targetPath}`);
            } else {
                logger.log(`Item was expected to be encrypted but signature missing: ${targetPath}`);
                // Try from backup? Backup IS encryptedString.
            }
        } else {
            // Plaintext: Content is already there. No decryption needed for FILE content.
            // But we should verify integrity? Hash check was done in Step 1.
            logger.log(`Item was locked in Plaintext mode. Flags removed.`);
        }
    } catch (error: any) {
        logger.log(`Failed to decrypt content: ${error.message}`);
        throw new Error(`Failed to decrypt content. Data might be corrupted.`);
    }

    // 4. Delete Lock File
    await fs.promises.unlink(lockFilePath);

    logger.log(`Unlocked successfully: ${targetPath}`);
}

