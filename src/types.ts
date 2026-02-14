
export interface ILogger {
    log(msg: string): void;
    show(): void;
}

export interface LockMetadata {
    token: string;
    hash: string;
    encryptedContent?: string;
    isEncrypted?: boolean;
    isDirectory?: boolean;
}
