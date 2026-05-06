import { createWriteStream } from 'node:fs';
import fs from 'fs/promises';
import os from 'os';
import path from 'path';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';
import { exec } from 'child_process';
import { SrtLogger } from '../logging/srt-logger.js';

const UV_VERSION = '0.11.10';

const PLATFORM_ASSETS: Record<string, Record<string, string>> = {
    linux: {
        x64: `uv-x86_64-unknown-linux-gnu.tar.gz`,
        arm64: `uv-aarch64-unknown-linux-gnu.tar.gz`,
    },
    darwin: {
        x64: `uv-x86_64-apple-darwin.tar.gz`,
        arm64: `uv-aarch64-apple-darwin.tar.gz`,
    },
    win32: {
        x64: `uv-x86_64-pc-windows-msvc.zip`,
        arm64: `uv-aarch64-pc-windows-msvc.zip`,
    },
};

export class UvManager {
    private static readonly BIN_DIR = path.join(os.homedir(), '.srt', 'bin');

    public static getUvPath(): string {
        const exe = process.platform === 'win32' ? 'uv.exe' : 'uv';
        return path.join(UvManager.BIN_DIR, exe);
    }

    public static async isUvInstalled(): Promise<boolean> {
        try {
            await fs.access(UvManager.getUvPath(), fs.constants.X_OK);
            return true;
        } catch {
            return false;
        }
    }

    public static async ensureUvAvailable(): Promise<string> {
        const uvPath = UvManager.getUvPath();
        if (await UvManager.isUvInstalled()) return uvPath;

        await UvManager.downloadUv();
        return uvPath;
    }

    private static async downloadUv(): Promise<void> {
        const asset = UvManager.getAssetName();
        const url = `https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/${asset}`;

        await fs.mkdir(UvManager.BIN_DIR, { recursive: true });

        const tempPath = path.join(UvManager.BIN_DIR, asset);

        try {
            const response = await fetch(url);
            if (!response.ok || !response.body) {
                throw new Error(`Download failed: ${response.status} ${response.statusText}`);
            }

            const fileStream = createWriteStream(tempPath);
            await pipeline(Readable.fromWeb(response.body as any), fileStream);

            await UvManager.extractBinary(tempPath);
        } finally {
            await fs.rm(tempPath, { force: true });
        }

        if (process.platform !== 'win32') {
            await fs.chmod(UvManager.getUvPath(), 0o755);
        }

        await UvManager.verifyInstallation();
    }

    private static async extractBinary(archivePath: string): Promise<void> {
        if (archivePath.endsWith('.zip')) {
            await UvManager.execAsync(`powershell -Command "Expand-Archive -Path '${archivePath}' -DestinationPath '${UvManager.BIN_DIR}' -Force"`, UvManager.BIN_DIR);
        } else {
            await UvManager.execAsync(`tar -xzf "${archivePath}" --strip-components=1 -C "${UvManager.BIN_DIR}"`, UvManager.BIN_DIR);
        }
    }

    private static async verifyInstallation(): Promise<void> {
        const uvPath = UvManager.getUvPath();
        try {
            await UvManager.execAsync(`"${uvPath}" --version`, UvManager.BIN_DIR);
        } catch (error) {
            await fs.rm(uvPath, { force: true });
            throw new Error('Failed to verify uv installation. Please check your internet connection and try again.');
        }
    }

    private static getAssetName(): string {
        const platformAssets = PLATFORM_ASSETS[process.platform];
        if (!platformAssets) {
            throw new Error(`Unsupported platform: ${process.platform}`);
        }

        const asset = platformAssets[process.arch];
        if (!asset) {
            throw new Error(`Unsupported architecture: ${process.arch} on ${process.platform}`);
        }

        return asset;
    }

    private static execAsync(command: string, cwd: string): Promise<string> {
        return new Promise((resolve, reject) => {
            exec(command, { cwd }, (error, stdout) => {
                if (error) {
                    SrtLogger.logError(`uv command failed: ${command}`, error);
                    reject(error);
                } else {
                    resolve(stdout);
                }
            });
        });
    }
}
