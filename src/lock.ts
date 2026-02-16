

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

// Helper to stream tar directly to output
async function pipeTarToStream(cwd: string, target: string, outputStream: NodeJS.WritableStream): Promise<void> {
    const tarStream = tar.c({
        cwd: cwd,
        gzip: false
    }, [target]);

    return new Promise((resolve, reject) => {
        tarStream.pipe(outputStream);
        tarStream.on('end', resolve);
        tarStream.on('error', reject);
        outputStream.on('error', reject);
    });
}

// Helper to extract tar stream
async function extractTarStream(inputStream: NodeJS.ReadableStream, cwd: string): Promise<void> {
    const extract = tar.x({
        cwd: cwd
    });

    return new Promise((resolve, reject) => {
        inputStream.pipe(extract)
            .on('finish', resolve)
            .on('error', reject);
        inputStream.on('error', reject);
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

    // Setup temporary file for encrypted content (streaming destination)
    // We use a temp file in the same directory to avoid crossing filesystem boundaries
    const tempEncryptedPath = `${targetPath}.tmp.enc`;

    // We also need to calculate hash. We can do it by reading the temp file after encryption?
    // Or we can assume security of GCM Tag is enough for integrity of "Encrypted Content".
    // But we need a hash of the ORIGINAL content for Plaintext Lock integrity?
    // For Encrypted Lock, checking the hash of the ENCRYPTED file is easier.
    // Let's stick to hashing the Final On-Disk Content.

    let finalHash = "";

    try {
        if (options.encrypt) {
            const output = fs.createWriteStream(tempEncryptedPath);

            if (isDirectory) {
                logger.log("  Target is a directory. Streaming tar to encryption...");

                // Pipe Tar -> EncryptStream -> File
                // Logic: We need a readable stream for EncryptStream. 
                // Types: encryptStream(input: Readable, output: Writable, pass)

                const tarStream = tar.c({ cwd: targetDir, gzip: false }, [targetName]);
                await import('./crypto_string').then(m => m.encryptStream(tarStream as unknown as NodeJS.ReadableStream, output, password));
            } else {
                logger.log("  Target is a file. Streaming to encryption...");
                const input = fs.createReadStream(targetPath);
                await import('./crypto_string').then(m => m.encryptStream(input, output, password));
            }

            // Now we have encrypted content in tempEncryptedPath
            // Hash it
            finalHash = await calculateFileHash(tempEncryptedPath);

        } else {
            // Plaintext Lock: We don't change content.
            // But we can't really "stream encrypt" a directory in place for Plaintext Lock?
            // "Plaintext Lock" for directory is weird. 
            // In original code, it seemed to force encryption for directories.
            // Let's keep that logic: Force encrypt for directories.
            if (isDirectory) {
                logger.log("  Directory detected. Forcing encryption for directory lock.");
                // Recursive call with encrypt=true logic? OR just fall through
                options.encrypt = true;

                const output = fs.createWriteStream(tempEncryptedPath);
                const tarStream = tar.c({ cwd: targetDir, gzip: false }, [targetName]);
                await import('./crypto_string').then(m => m.encryptStream(tarStream as unknown as NodeJS.ReadableStream, output, password));

                finalHash = await calculateFileHash(tempEncryptedPath);
            } else {
                // Plaintext File:
                // Just hash the current file
                finalHash = await calculateFileHash(targetPath);
            }
        }

        // 4. Create Metadata Token
        const metadata: LockMetadata = {
            token: VERIFICATION_TOKEN,
            hash: finalHash,
            // encryptedContent: Removed! We no longer store content in JSON.
            isEncrypted: options.encrypt,
            isDirectory: isDirectory
        };
        const encryptedMetadata = await encryptData(JSON.stringify(metadata), password);

        // 5. Commit Changes
        if (options.encrypt) {
            // Replace original with encrypted
            if (isDirectory) {
                await fs.promises.rm(targetPath, { recursive: true, force: true });
            }
            await fs.promises.rename(tempEncryptedPath, targetPath);
        } else {
            // Plaintext: content already there.
        }

        // 6. Write Metadata
        await fs.promises.writeFile(lockFilePath, encryptedMetadata, 'utf8');

        // 7. Permission Flags
        await execAsync(`chmod a-w "${targetPath}"`);
        await execAsync(`chflags uchg "${targetPath}"`);
        logger.log(`Item locked & encrypted successfully: ${targetPath}`);

    } catch (error: any) {
        // Cleanup temp file
        if (fs.existsSync(tempEncryptedPath)) {
            await fs.promises.unlink(tempEncryptedPath);
        }

        logger.log(`Locking failed: ${error.message}`);
        throw error;
    }
}

export async function unlockFile(targetPath: string, password: string, logger: ILogger) {
    logger.log(`Unlocking: ${targetPath}`);

    const lockFilePath = `${targetPath}.obscuro-lock`;
    const targetDir = path.dirname(targetPath);

    if (!fs.existsSync(lockFilePath)) {
        throw new Error(`No lock file found (${lockFilePath}). Cannot verify password.`);
    }

    // 1. Read Metadata
    let metadata: LockMetadata;
    try {
        const encryptedMetadata = await fs.promises.readFile(lockFilePath, 'utf8');
        const decryptedMetadataBuffer = await decryptData(encryptedMetadata, password);
        metadata = JSON.parse(decryptedMetadataBuffer.toString('utf8'));
    } catch (e: any) {
        if (e.message.includes('password') || e.message.includes('MAC mismatch')) {
            throw new Error("Invalid password.");
        }
        throw new Error("Corrupt lock file.");
    }

    if (metadata.token !== VERIFICATION_TOKEN) {
        throw new Error("Invalid password (token mismatch)."); // Shouldn't happen if decryption succeeded
    }

    // 2. Integrity Check
    if (metadata.hash) {
        const currentHash = await calculateFileHash(targetPath);
        if (currentHash !== metadata.hash) {
            throw new Error("Integrity check failed! The item has been externally modified.");
        }
    }

    // 3. Remove Flags
    try {
        await execAsync(`chflags nouchg "${targetPath}"`);
        await execAsync(`chmod u+w "${targetPath}"`);
    } catch (error: any) {
        throw new Error(`Failed to remove read-only flag: ${error.message}`);
    }

    // 4. Decrypt Content
    try {
        const isEncrypted = metadata.isEncrypted ?? true;
        const isDirectory = metadata.isDirectory ?? false;

        if (isEncrypted) {
            // Check header to see if it is Legacy (OBSCURO:) or Streaming (Binary)
            // We can read first 8 bytes
            const fd = await fs.promises.open(targetPath, 'r');
            const header = Buffer.alloc(8);
            await fd.read(header, 0, 8, 0);
            await fd.close();

            const isLegacy = header.toString().startsWith("OBSCURO:");

            // Prepare temp output for decryption
            const tempDecryptedPath = `${targetPath}.tmp.dec`;

            if (isLegacy) {
                logger.log("Legacy format detected. Unlocking in memory (Warning: High RAM usage for large files).");
                const content = await fs.promises.readFile(targetPath, 'utf8');
                // If legacy, it might be inside metadata.encryptedContent too?
                // No, standard flow is content on disk.
                // Wait, legacy `lockFile` wrote content to disk OR stored in metadata
                // The old code: `encryptedString = metadata.encryptedContent` OR `readFile(targetPath)`

                let decryptedBuffer: Buffer;

                if (metadata.encryptedContent) {
                    // Very old legacy (content in metadata)
                    decryptedBuffer = await decryptData(metadata.encryptedContent, password);
                } else {
                    decryptedBuffer = await decryptData(content, password);
                }

                if (isDirectory) {
                    await fs.promises.unlink(targetPath); // Remove the file "placeholder"
                    // Restore directory
                    await extractTarBuffer(decryptedBuffer, targetDir);
                } else {
                    await fs.promises.writeFile(targetPath, decryptedBuffer);
                }
            } else {
                // Streaming Decryption
                const input = fs.createReadStream(targetPath);

                if (isDirectory) {
                    // Decrypt Stream -> Untar Stream
                    // This is tricky: `decryptStream` takes an output stream.
                    // But we want to feed that output into `tar.x`.
                    // We can pipe `decryptStream` output to a PassThrough?
                    // No, `decryptStream` writes to a Writable.

                    // We can pipe to a temp TAR file, then extract it?
                    // Or implement `decryptStream` to return a Readable?
                    // Current implementation: `decryptStream(input, output)`

                    // Option 1: Decrypt to temp tar file
                    const tempTar = `${targetPath}.tar`;
                    const output = fs.createWriteStream(tempTar);

                    await import('./crypto_string').then(m => m.decryptStream(input, output, password));

                    // Now extract tar
                    await fs.promises.unlink(targetPath); // Remove encrypted file

                    // Extract
                    await tar.x({ file: tempTar, cwd: targetDir });

                    await fs.promises.unlink(tempTar);

                } else {
                    // File: Decrypt Stream -> File Stream (temp) -> Rename
                    const output = fs.createWriteStream(tempDecryptedPath);
                    await import('./crypto_string').then(m => m.decryptStream(input, output, password));

                    await fs.promises.rename(tempDecryptedPath, targetPath);
                }
            }
        }

    } catch (error: any) {
        logger.log(`Failed to decrypt content: ${error.message}`);
        throw error; // Re-throw so user knows
    }

    // 5. Cleanup Lock
    await fs.promises.unlink(lockFilePath);
    logger.log(`Unlocked successfully: ${targetPath}`);
}

// Helpers
async function calculateFileHash(filePath: string): Promise<string> {
    return new Promise((resolve, reject) => {
        const hash = crypto.createHash('sha256');
        const stream = fs.createReadStream(filePath);
        stream.on('data', d => hash.update(d));
        stream.on('end', () => resolve(hash.digest('hex')));
        stream.on('error', reject);
    });
}

