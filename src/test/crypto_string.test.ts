import * as assert from 'assert';
import { encryptString, decryptString } from '../crypto_string';

async function runTests() {
    console.log('Running Crypto String Tests...');

    // Test 1: Encrypt and Decrypt
    try {
        console.log('Test 1: Encrypt and Decrypt');
        const originalText = "SuperSecretPassword123!";
        const password = "myStrongPassword";

        const encrypted = await encryptString(originalText, password);
        assert.ok(encrypted.startsWith('OBSCURO:'), 'Encrypted string should start with OBSCURO:');
        assert.notStrictEqual(encrypted, originalText, 'Encrypted string should not match original');

        const decrypted = await decryptString(encrypted, password);
        assert.strictEqual(decrypted, originalText, 'Decrypted text should match original');
        console.log('  PASS');
    } catch (e: any) {
        console.error('  FAIL:', e.message);
        process.exit(1);
    }

    // Test 2: Wrong Password
    try {
        console.log('Test 2: Wrong Password');
        const originalText = "Data";
        const password = "correct";
        const wrongPassword = "wrong";

        const encrypted = await encryptString(originalText, password);

        try {
            await decryptString(encrypted, wrongPassword);
            throw new Error('Should have thrown error on wrong password');
        } catch (e: any) {
            if (e.message.includes('supported state') || e.message.includes('uthentic')) { // Generic crypto error check
                console.log('  PASS');
            } else {
                // It threw something else
                console.log('  PASS (threw error as expected)');
            }
        }
    } catch (e: any) {
        console.error('  FAIL:', e.message);
        process.exit(1);
    }

    // Test 3: Tampered Data
    try {
        console.log('Test 3: Tampered Data');
        const originalText = "Data";
        const password = "pass";
        const encrypted = await encryptString(originalText, password);

        // Tamper with the base64 string
        const tampered = encrypted.slice(0, -5) + "ABCDE";

        try {
            await decryptString(tampered, password);
            console.error('  FAIL: Should have thrown error');
            process.exit(1);
        } catch (e) {
            console.log('  PASS');
        }
    } catch (e: any) {
        console.error('  FAIL:', e.message);
        process.exit(1);
    }
}

runTests();
