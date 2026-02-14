import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as tar from 'tar';
import { pipeline } from 'stream';
import { promisify } from 'util';
import { ILogger } from './types';

const pipelineAsync = promisify(pipeline);

export async function encryptFile(targetPath: string, sourceFile: string, password: string, logger: ILogger, options: { keepOriginal?: boolean } = {}) {
    logger.log(`Starting encryption for ${targetPath}`);
    logger.show();

    // 1. Create tarball (temp file)
    const tempTarPath = path.join(path.dirname(targetPath), `.temp_${Date.now()}.tar`);

    try {
        await tar.c({
            file: tempTarPath,
            cwd: path.dirname(sourceFile),
        }, [path.basename(sourceFile)]);

        // 2. Encrypt using streams
        const salt = crypto.randomBytes(16);
        const iv = crypto.randomBytes(12); // GCM standard IV size

        // Use async pbkdf2 to avoid blocking the event loop
        const key = await new Promise<Buffer>((resolve, reject) =>
            crypto.pbkdf2(password, salt, 100000, 32, 'sha256', (err, k) => err ? reject(err) : resolve(k))
        );

        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const outputFilename = `${targetPath}.obscuro`;

        const readStream = fs.createReadStream(tempTarPath);
        const writeStream = fs.createWriteStream(outputFilename);

        // Format: Salt(16) + IV(12) + Tag(16) + EncryptedData
        // Write header placeholder: Salt + IV + Empty Tag
        const header = Buffer.concat([salt, iv, Buffer.alloc(16)]);
        if (!writeStream.write(header)) {
            await new Promise(resolve => writeStream.once('drain', () => resolve(undefined)));
        }

        // Pipe streams
        await pipelineAsync(readStream, cipher, writeStream);

        // Write the Auth Tag at the correct position
        const tag = cipher.getAuthTag();
        const fd = await fs.promises.open(outputFilename, 'r+');
        try {
            // Write tag at offset 28 (16 + 12)
            await fd.write(tag, 0, 16, 28);
        } finally {
            await fd.close();
        }

        // 3. Cleanup
        await fs.promises.unlink(tempTarPath);

        // Secure delete original ONLY if keepOriginal is false (default)
        if (!options.keepOriginal && fs.existsSync(targetPath)) {
            if (fs.statSync(targetPath).isDirectory()) {
                fs.rmSync(targetPath, { recursive: true, force: true });
            } else {
                fs.unlinkSync(targetPath);
            }
        }

        // If we encrypted a different file (e.g. compiled binary), delete it too
        if (sourceFile !== targetPath && fs.existsSync(sourceFile)) {
            fs.unlinkSync(sourceFile);
        }

    } catch (e) {
        // Cleanup temp file if exists
        if (fs.existsSync(tempTarPath)) {
            fs.unlinkSync(tempTarPath);
        }
        throw e;
    }
}

export async function decryptFile(filePath: string, password: string, logger: ILogger, cleanupCallback?: (originalPath: string) => void) {
    // Read header (Salt + IV + Tag) = 44 bytes
    const fd = await fs.promises.open(filePath, 'r');
    const header = Buffer.alloc(44);
    const { bytesRead } = await fd.read(header, 0, 44, 0);
    await fd.close();

    if (bytesRead < 44) {
        throw new Error("File is too short to be a valid Obscuro file.");
    }

    const salt = header.subarray(0, 16);
    const iv = header.subarray(16, 28);
    const tag = header.subarray(28, 44);

    const key = await new Promise<Buffer>((resolve, reject) =>
        crypto.pbkdf2(password, salt, 100000, 32, 'sha256', (err, k) => err ? reject(err) : resolve(k))
    );

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);

    const outputDir = path.dirname(filePath);
    const tempTarPath = path.join(outputDir, `.temp_decrypt_${Date.now()}.tar`);

    try {
        const readStream = fs.createReadStream(filePath, { start: 44 });
        const writeStream = fs.createWriteStream(tempTarPath);

        await pipelineAsync(readStream, decipher, writeStream);

        await tar.x({
            file: tempTarPath,
            cwd: outputDir
        });

        // Cleanup
        await fs.promises.unlink(tempTarPath);
        await fs.promises.unlink(filePath); // Delete encrypted file on success

        // Invoke custom cleanup (e.g. removing python binaries)
        if (cleanupCallback) {
            const originalPath = filePath.replace('.obscuro', '');
            cleanupCallback(originalPath);
        }

    } catch (e) {
        if (fs.existsSync(tempTarPath)) {
            fs.unlinkSync(tempTarPath);
        }
        throw e;
    }
}
