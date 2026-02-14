import * as vscode from 'vscode';
import { ILogger } from './types';

export class Logger implements ILogger {
    private channel: vscode.OutputChannel;

    constructor(channel: vscode.OutputChannel) {
        this.channel = channel;
    }

    log(msg: string) {
        this.channel.appendLine(`[${new Date().toISOString()}] ${msg}`);
    }

    show() {
        this.channel.show();
    }
}
