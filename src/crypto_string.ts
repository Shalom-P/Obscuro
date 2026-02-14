import * as crypto from 'crypto';

/**
 * Encrypts data (string or Buffer) using AES-256-GCM.
 * Format: OBSCURO:<base64(salt + iv + tag + ciphertext)>
 */
export async function encryptData(data: string | Buffer, password: string): Promise<string> {
    const salt = crypto.randomBytes(16);
    const iv = crypto.randomBytes(12);

    const key = await new Promise<Buffer>((resolve, reject) =>
        crypto.pbkdf2(password, salt, 100000, 32, 'sha256', (err, k) => err ? reject(err) : resolve(k))
    );

    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

    // Accept string or Buffer
    let encrypted: Buffer;
    if (typeof data === 'string') {
        encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
    } else {
        encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    }

    const tag = cipher.getAuthTag();

    // Combine: Salt(16) + IV(12) + Tag(16) + Ciphertext
    const combined = Buffer.concat([salt, iv, tag, encrypted]);
    return `OBSCURO:${combined.toString('base64')}`;
}

/**
 * Decrypts an OBSCURO string and returns Buffer.
 */
export async function decryptData(encryptedString: string, password: string): Promise<Buffer> {
    if (!encryptedString.startsWith('OBSCURO:')) {
        throw new Error("Invalid format. String must start with 'OBSCURO:'.");
    }

    const base64Data = encryptedString.substring(8); // Remove "OBSCURO:"
    const data = Buffer.from(base64Data, 'base64');

    if (data.length < 44) { // 16 + 12 + 16
        throw new Error("Invalid data length.");
    }

    const salt = data.subarray(0, 16);
    const iv = data.subarray(16, 28);
    const tag = data.subarray(28, 44);
    const ciphertext = data.subarray(44);

    const key = await new Promise<Buffer>((resolve, reject) =>
        crypto.pbkdf2(password, salt, 100000, 32, 'sha256', (err, k) => err ? reject(err) : resolve(k))
    );

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);

    let decrypted = decipher.update(ciphertext);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return decrypted;
}

/**
 * Helper to decrypt and return string (for backward compatibility or text files).
 */
export async function decryptString(encryptedString: string, password: string): Promise<string> {
    const buffer = await decryptData(encryptedString, password);
    return buffer.toString('utf8');
}

/**
 * Helper to encrypt string (wrapper for consistency).
 */
export async function encryptString(text: string, password: string): Promise<string> {
    return encryptData(text, password);
}
