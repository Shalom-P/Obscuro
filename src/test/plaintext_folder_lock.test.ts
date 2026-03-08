import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import { lockFile, unlockFile } from '../lock';
import { ILogger } from '../types';

const TEST_DIR = path.join(__dirname, 'test_folder_lock_plaintext');
const TEST_FILE_1 = path.join(TEST_DIR, 'main.cpp');
const TEST_FILE_2 = path.join(TEST_DIR, 'subdir', 'main.hpp');
const TEST_DIR_SUB = path.join(TEST_DIR, 'subdir');

const LOCK_FILE = `${TEST_DIR}.obscuro-lock`;
const PASSWORD = "testpassword123";

const mockLogger: ILogger = {
    log: (msg: string) => console.log(`[LOG]: ${msg}`),
    show: () => { }
};

async function runTests() {
    console.log('Running Plaintext Folder Lock Tests...');
    
    // Setup
    if (fs.existsSync(TEST_DIR)) fs.rmSync(TEST_DIR, { recursive: true, force: true });
    if (fs.existsSync(LOCK_FILE)) fs.unlinkSync(LOCK_FILE);

    fs.mkdirSync(TEST_DIR);
    fs.mkdirSync(TEST_DIR_SUB);
    fs.writeFileSync(TEST_FILE_1, "int main() {}", 'utf8');
    fs.writeFileSync(TEST_FILE_2, "#pragma once", 'utf8');

    try {
        console.log('Test 1: Lock Folder (Plaintext)');
        await lockFile(TEST_DIR, PASSWORD, mockLogger, { encrypt: false });

        // Verify folder and files exist
        assert.ok(fs.existsSync(TEST_DIR) && fs.statSync(TEST_DIR).isDirectory(), 'Directory should exist');
        assert.ok(fs.existsSync(TEST_FILE_1), 'File 1 should exist');
        assert.ok(fs.existsSync(TEST_FILE_2), 'File 2 should exist');
        
        // Verify we cannot write to the files (EACCES/EPERM expected)
        let cannotWrite = false;
        try {
            fs.appendFileSync(TEST_FILE_1, "test");
        } catch (e: any) {
            cannotWrite = true;
        }
        assert.ok(cannotWrite, 'Should not be able to write to nested file 1 when locked');

        console.log('  PASS (Locked)');

        console.log('Test 2: Unlock Folder (Plaintext)');
        await unlockFile(TEST_DIR, PASSWORD, mockLogger);

        // Verify we can write to files again
        try {
            fs.appendFileSync(TEST_FILE_1, "\n// Can edit");
            fs.appendFileSync(TEST_FILE_2, "\n// Can edit");
        } catch (e: any) {
             assert.fail(`Should be able to write to files after unlock. Error: ${e.message}`);
        }

        assert.ok(!fs.existsSync(LOCK_FILE), 'Lock file should be gone');
        console.log('  PASS (Unlocked)');

    } catch (e: any) {
        console.error('  FAIL:', e.message);
        console.error(e.stack);
        process.exit(1);
    } finally {
        // Cleanup
        if (fs.existsSync(TEST_DIR)) fs.rmSync(TEST_DIR, { recursive: true, force: true });
        if (fs.existsSync(LOCK_FILE)) fs.unlinkSync(LOCK_FILE);
    }
}

runTests();
