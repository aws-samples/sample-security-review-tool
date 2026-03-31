import { execFileSync } from 'child_process';
import * as fs from 'fs';
import { DownloadResult } from './types.js';
import { ArchiveExtractor } from './archive-extractor.js';

const REQUEST_TIMEOUT = 30000;

export class BinaryDownloader {
    public static async download(url: string, targetPath: string): Promise<DownloadResult> {
        try {
            execFileSync('curl', ['-L', '-o', targetPath, url], {
                timeout: REQUEST_TIMEOUT,
                stdio: ['ignore', 'pipe', 'pipe']
            });

            if (!fs.existsSync(targetPath)) {
                return { success: false, error: 'File not created' };
            }

            const stats = fs.statSync(targetPath);
            if (stats.size === 0) {
                fs.unlinkSync(targetPath);
                return { success: false, error: 'Empty file' };
            }

            if (url.includes('.tar.gz') || url.includes('.zip')) {
                const extractDir = `${targetPath}_extracted`;

                const extractedBinaryPath = await ArchiveExtractor.extract(targetPath, extractDir);

                if (!extractedBinaryPath) {
                    this.cleanup(targetPath, extractDir);
                    return { success: false, error: 'Binary not found in archive' };
                }

                fs.unlinkSync(targetPath);
                fs.renameSync(extractedBinaryPath, targetPath);
                fs.rmSync(extractDir, { recursive: true, force: true });
            }

            return { success: true, binaryPath: targetPath };
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';

            try {
                if (fs.existsSync(targetPath)) {
                    fs.unlinkSync(targetPath);
                }
                const extractDir = `${targetPath}_extracted`;
                if (fs.existsSync(extractDir)) {
                    fs.rmSync(extractDir, { recursive: true, force: true });
                }
            } catch (cleanupError) {
                // Ignore cleanup errors
            }

            return { success: false, error: errorMessage };
        }
    }

    private static cleanup(targetPath: string, extractDir: string): void {
        try {
            if (fs.existsSync(targetPath)) {
                fs.unlinkSync(targetPath);
            }
            if (fs.existsSync(extractDir)) {
                fs.rmSync(extractDir, { recursive: true, force: true });
            }
        } catch (error) {
            // Ignore cleanup errors
        }
    }
}
