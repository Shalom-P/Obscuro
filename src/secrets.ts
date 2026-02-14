import * as vscode from 'vscode';

export class SecretManager {
    private secrets: vscode.SecretStorage;

    constructor(context: vscode.ExtensionContext) {
        this.secrets = context.secrets;
    }

    private getKey(targetPath: string): string {
        return `obscuro.password.${targetPath}`;
    }

    async storePassword(targetPath: string, password: string): Promise<void> {
        await this.secrets.store(this.getKey(targetPath), password);
    }

    async getPassword(targetPath: string): Promise<string | undefined> {
        return await this.secrets.get(this.getKey(targetPath));
    }

    async deletePassword(targetPath: string): Promise<void> {
        await this.secrets.delete(this.getKey(targetPath));
    }
}
