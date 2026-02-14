
import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import { lockFile, unlockFile } from '../lock';
import { ILogger } from '../types';

const TEST_FILE = path.join(__dirname, 'test_integrity.txt');
const LOCK_FILE = `${TEST_FILE}.obscuro-lock`;
const PASSWORD = "testpassword123";

// Mock Logger
const mockLogger: ILogger = {
    log: (msg: string) => console.log(`[LOG]: ${msg}`),
    show: () => { }
};

async function runTests() {
    console.log('Running Integrity Tests...');

    // Setup: Create test file
    fs.writeFileSync(TEST_FILE, "Original Content", 'utf8');

    // Test 1: Normal Lock and Unlock
    try {
        console.log('Test 1: Normal Lock and Unlock');
        await lockFile(TEST_FILE, PASSWORD, mockLogger);

        // Check if locked
        assert.ok(fs.existsSync(LOCK_FILE), 'Lock file should exist');

        // Unlock
        await unlockFile(TEST_FILE, PASSWORD, mockLogger);

        // Verify content
        const content = fs.readFileSync(TEST_FILE, 'utf8');
        assert.strictEqual(content, "Original Content", 'Content should match original');
        console.log('  PASS');
    } catch (e: any) {
        console.error('  FAIL:', e.message);
        process.exit(1);
    }

    // Test 2: Tamper Detection
    try {
        console.log('Test 2: Tamper Detection');

        // Setup scenarios
        fs.writeFileSync(TEST_FILE, "Secret Data", 'utf8');
        await lockFile(TEST_FILE, PASSWORD, mockLogger);

        // TAMPER: Manually change file flags and content
        // 1. Remove immutable flag (simulating admin bypass)
        try {
            const { execSync } = require('child_process');
            execSync(`chflags nouchg "${TEST_FILE}"`);
            execSync(`chmod u+w "${TEST_FILE}"`);
        } catch (e) {
            // Ignore if fails (might not be immutable on all systems/tests)
        }

        // 2. Modify content
        fs.writeFileSync(TEST_FILE, "Tampered Data", 'utf8');

        // Attempt unlock
        try {
            await unlockFile(TEST_FILE, PASSWORD, mockLogger);
            console.error('  FAIL: Should have detected tampering!');
            process.exit(1);
        } catch (e: any) {
            if (e.message.includes('integrity check failed')) {
                console.log('  PASS (Caught tampering)');
            } else {
                console.error('  FAIL: Unexpected error:', e.message);
                process.exit(1);
            }
        }

    } catch (e: any) {
        console.error('  FAIL:', e.message);
        process.exit(1);
    } finally {
        // Cleanup
        if (fs.existsSync(TEST_FILE)) {
            try {
                const { execSync } = require('child_process');
                execSync(`chflags nouchg "${TEST_FILE}"`);
                fs.unlinkSync(TEST_FILE);
            } catch { }
        }
        if (fs.existsSync(LOCK_FILE)) fs.unlinkSync(LOCK_FILE);
    }
}

runTests();
