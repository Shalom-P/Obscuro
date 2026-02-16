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

/**
 * Encrypts a stream using AES-256-GCM.
 * Output Format: Salt(16) + IV(12) + EncryptedData + Tag(16)
 */
export async function encryptStream(inputStream: NodeJS.ReadableStream, outputStream: NodeJS.WritableStream, password: string): Promise<void> {
    const salt = crypto.randomBytes(16);
    const iv = crypto.randomBytes(12);

    const key = await new Promise<Buffer>((resolve, reject) =>
        crypto.pbkdf2(password, salt, 100000, 32, 'sha256', (err, k) => err ? reject(err) : resolve(k))
    );

    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

    // Write Header: Salt + IV
    outputStream.write(salt);
    outputStream.write(iv);

    return new Promise((resolve, reject) => {
        inputStream.pipe(cipher).pipe(outputStream, { end: false });

        cipher.on('end', () => {
            // Write Auth Tag at the end
            const tag = cipher.getAuthTag();
            outputStream.write(tag);
            outputStream.end();
            resolve();
        });

        inputStream.on('error', reject);
        cipher.on('error', reject);
        outputStream.on('error', reject);
    });
}

/**
 * Decrypts a stream that was encrypted with encryptStream.
 * Expects Input Format: Salt(16) + IV(12) + EncryptedData + Tag(16)
 * Note: Stream decryption with GCM usually requires the tag at the end.
 * However, Node's Decipher with GCM needs setAuthTag called BEFORE final(),
 * or passed in the constructor if possible (but tag is at end).
 * For streams where we can't seek (like network), this is tricky with standard pipe.
 * But for local files we can read the header (Wait! Tag is at the end!).
 *
 * Actually, standard GCM stream decryption in Node 
 * requires us to know the tag before we finish processing? 
 * No, `decipher.setAuthTag(tag)` can be called anytime before `final()`.
 * But we need to EXTRACT it from the stream *before* we pipe everything to decipher? 
 * Or we buffer the last 16 bytes?
 *
 * Strategy:
 * 1. Read first 28 bytes (Salt + IV).
 * 2. Transform stream: Pushing data to decipher, keeping a 16-byte rolling buffer.
 *    When stream ends, the buffer IS the tag. 
 *    Then call `setAuthTag` and `final`.
 */
export async function decryptStream(inputStream: NodeJS.ReadableStream, outputStream: NodeJS.WritableStream, password: string): Promise<void> {
    // We need to read the header manually first
    const headerBuffer = await readBytesFromStream(inputStream, 28);
    const salt = headerBuffer.subarray(0, 16);
    const iv = headerBuffer.subarray(16, 28);

    const key = await new Promise<Buffer>((resolve, reject) =>
        crypto.pbkdf2(password, salt, 100000, 32, 'sha256', (err, k) => err ? reject(err) : resolve(k))
    );

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);

    // We need to intercept the stream to hold back the last 16 bytes (Auth Tag)
    // and pipe the rest to decipher.

    let tagBuffer = Buffer.alloc(0);

    return new Promise((resolve, reject) => {
        // Pipe decipher output to outputStream
        // We set this up first so data flows as soon as we write to decipher
        decipher.pipe(outputStream);

        // Handle errors on all streams
        inputStream.on('error', reject);
        decipher.on('error', reject);
        outputStream.on('error', reject);

        // Handle finish/end
        outputStream.on('finish', resolve);

        inputStream.on('data', (chunk: Buffer) => {
            // Append new chunk to what we have
            // console.log(`[DEBUG] decryptStream got chunk: ${chunk.length}`); // optional debug
            const total = Buffer.concat([tagBuffer, chunk]);

            if (total.length > 16) {
                // If we have more than 16 bytes, we can push the excess to decipher
                // The last 16 bytes must remain in tagBuffer
                const toDecrypt = total.subarray(0, total.length - 16);
                tagBuffer = total.subarray(total.length - 16);

                // Write to decipher
                decipher.write(toDecrypt);
            } else {
                // Just keep it in buffer
                tagBuffer = total;
            }
        });

        // Resuming input stream to ensure data flows after header read
        (inputStream as any).resume();

        inputStream.on('end', () => {
            // Stream ended. tagBuffer should be exactly 16 bytes (the Tag).
            if (tagBuffer.length !== 16) {
                reject(new Error("Stream ended but auth tag missing or incomplete."));
                return;
            }

            try {
                decipher.setAuthTag(tagBuffer);
                // End the decipher stream. It will process remaining internal buffer, verify tag, and emit 'end'.
                decipher.end();
            } catch (e) {
                reject(new Error("Decryption setup failed: " + e));
            }
        });
    });
}

// Helper to read exactly N bytes from a stream (for header)
function readBytesFromStream(stream: NodeJS.ReadableStream, n: number): Promise<Buffer> {
    return new Promise((resolve, reject) => {
        let buffer = Buffer.alloc(0);

        const onData = (chunk: Buffer) => {
            buffer = Buffer.concat([buffer, chunk]);
            if (buffer.length >= n) {
                cleanup();
                // We have enough. 
                // IMPORTANT: The stream might have emitted more than N.
                // We need to "unshift" the excess back onto the stream so the next consumer sees it.
                // However, standard Readable `unshift` works.
                const result = buffer.subarray(0, n);
                const excess = buffer.subarray(n);

                if (excess.length > 0) {
                    (stream as any).unshift(excess);
                }
                resolve(result);
            }
        };

        const onError = (err: Error) => {
            cleanup();
            reject(err);
        };

        const cleanup = () => {
            stream.off('data', onData);
            stream.off('error', onError);
            // We pause to stop flow until next consumer is attached
            (stream as any).pause();
        };

        stream.on('data', onData);
        stream.on('error', onError);
        (stream as any).resume(); // Ensure flowing
    });
}
