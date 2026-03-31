import { execFileSync } from 'child_process';
import * as fs from 'fs';
import { InstallResult, TestResult } from './types.js';

export class BinaryInstaller {
    public static install(newBinaryPath: string, targetPath: string): InstallResult {
        try {
            const oldBinaryPath = `${targetPath}.old`;

            if (process.platform !== 'win32') {
                fs.chmodSync(newBinaryPath, 0o755);
            }

            fs.renameSync(targetPath, oldBinaryPath);
            fs.renameSync(newBinaryPath, targetPath);

            return { success: true };
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            return { success: false, error: errorMessage };
        }
    }

    public static test(binaryPath: string): TestResult {
        try {
            const result = execFileSync(binaryPath, ['--version'], {
                encoding: 'utf8',
                stdio: ['ignore', 'pipe', 'ignore']
            });
            const success = result.trim().length > 0;
            return { success };
        } catch (error) {
            return { success: false, error: 'Binary test failed' };
        }
    }

    public static rollback(targetPath: string): InstallResult {
        try {
            const oldBinaryPath = `${targetPath}.old`;

            if (!fs.existsSync(oldBinaryPath)) {
                return { success: false, error: 'No .old binary found for rollback' };
            }

            if (fs.existsSync(targetPath)) {
                fs.unlinkSync(targetPath);
            }

            fs.renameSync(oldBinaryPath, targetPath);
            return { success: true };
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            return { success: false, error: errorMessage };
        }
    }
}
