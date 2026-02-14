
import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import { lockFile, unlockFile } from '../lock';
import { ILogger } from '../types';

const TEST_DIR = path.join(__dirname, 'test_folder_lock');
const TEST_FILE_1 = path.join(TEST_DIR, 'file1.txt');
const TEST_FILE_2 = path.join(TEST_DIR, 'subdir', 'file2.bin');
const TEST_DIR_SUB = path.join(TEST_DIR, 'subdir');

const LOCK_FILE = `${TEST_DIR}.obscuro-lock`;
const PASSWORD = "testpassword123";

// Mock Logger
const mockLogger: ILogger = {
    log: (msg: string) => console.log(`[LOG]: ${msg}`),
    show: () => { }
};

async function runTests() {
    console.log('Running Folder Lock Tests...');

    // Setup: Create test directory structure
    if (fs.existsSync(TEST_DIR)) fs.rmSync(TEST_DIR, { recursive: true, force: true });
    if (fs.existsSync(LOCK_FILE)) fs.unlinkSync(LOCK_FILE);

    fs.mkdirSync(TEST_DIR);
    fs.mkdirSync(TEST_DIR_SUB);
    fs.writeFileSync(TEST_FILE_1, "Hello World from File 1", 'utf8');

    // Create purely binary content
    const binaryBuffer = Buffer.from([0x00, 0x01, 0x02, 0xFF, 0xFE]);
    fs.writeFileSync(TEST_FILE_2, binaryBuffer);

    // Test 1: Lock Folder
    try {
        console.log('Test 1: Lock Folder');
        await lockFile(TEST_DIR, PASSWORD, mockLogger);

        // Check if directory is replaced by file
        assert.ok(!fs.existsSync(TEST_DIR) || !fs.statSync(TEST_DIR).isDirectory(), 'Directory should not exist as a directory');
        assert.ok(fs.existsSync(TEST_DIR) && fs.statSync(TEST_DIR).isFile(), 'Encrypted file should exist in place of directory');

        // Check content header
        const content = fs.readFileSync(TEST_DIR, 'utf8');
        assert.ok(content.startsWith('OBSCURO:'), 'File content should start with OBSCURO:');

        // Check lock file
        assert.ok(fs.existsSync(LOCK_FILE), 'Lock file should exist');

        console.log('  PASS (Locked)');

        // Test 2: Unlock Folder
        console.log('Test 2: Unlock Folder');
        await unlockFile(TEST_DIR, PASSWORD, mockLogger);

        // Verify structure restored
        assert.ok(fs.existsSync(TEST_DIR) && fs.statSync(TEST_DIR).isDirectory(), 'Directory should be restored');
        assert.ok(fs.existsSync(TEST_FILE_1), 'File 1 should exist');
        assert.ok(fs.existsSync(TEST_FILE_2), 'File 2 should exist');

        // Verify content
        const content1 = fs.readFileSync(TEST_FILE_1, 'utf8');
        assert.strictEqual(content1, "Hello World from File 1", 'File 1 content mismatch');

        const content2 = fs.readFileSync(TEST_FILE_2);
        assert.ok(content2.equals(binaryBuffer), 'File 2 binary content mismatch');

        assert.ok(!fs.existsSync(LOCK_FILE), 'Lock file should be gone');

        console.log('  PASS (Unlocked)');

        // Test 3: Lock Single Binary File
        console.log('Test 3: Lock Single Binary File');
        const binFile = path.join(path.dirname(TEST_DIR), 'single_binary.bin');
        const binData = Buffer.from([0xAA, 0xBB, 0xCC, 0xDD]);
        fs.writeFileSync(binFile, binData);

        await lockFile(binFile, PASSWORD, mockLogger);

        // Check content
        const lockedContent = fs.readFileSync(binFile, 'utf8');
        assert.ok(lockedContent.startsWith('OBSCURO:'), 'Binary file should be encrypted');

        await unlockFile(binFile, PASSWORD, mockLogger);

        const unlockedData = fs.readFileSync(binFile);
        assert.ok(unlockedData.equals(binData), 'Binary content should match');
        fs.unlinkSync(binFile);

        console.log('  PASS (Single Binary)');

    } catch (e: any) {
        console.error('  FAIL:', e.message);
        console.error(e.stack);
        process.exit(1);
    } finally {
        // Cleanup
        if (fs.existsSync(TEST_DIR)) fs.rmSync(TEST_DIR, { recursive: true, force: true });
        if (fs.existsSync(LOCK_FILE)) fs.unlinkSync(LOCK_FILE);
        // Also cleanup just in case it failed in weird state where TEST_DIR is a file
        if (fs.existsSync(TEST_DIR) && fs.statSync(TEST_DIR).isFile()) fs.unlinkSync(TEST_DIR);
    }
}

runTests();
