import * as crypto from 'crypto';

/**
 * Encrypts a string using AES-256-GCM.
 * Format: OBSCURO:<base64(salt + iv + tag + ciphertext)>
 */
export async function encryptString(text: string, password: string): Promise<string> {
    const salt = crypto.randomBytes(16);
    const iv = crypto.randomBytes(12);

    const key = await new Promise<Buffer>((resolve, reject) =>
        crypto.pbkdf2(password, salt, 100000, 32, 'sha256', (err, k) => err ? reject(err) : resolve(k))
    );

    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let encrypted = cipher.update(text, 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const tag = cipher.getAuthTag();

    // Combine: Salt(16) + IV(12) + Tag(16) + Ciphertext
    const combined = Buffer.concat([salt, iv, tag, encrypted]);
    return `OBSCURO:${combined.toString('base64')}`;
}

/**
 * Decrypts an OBSCURO string.
 */
export async function decryptString(encryptedString: string, password: string): Promise<string> {
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

    return decrypted.toString('utf8');
}
