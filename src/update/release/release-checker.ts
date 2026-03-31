import chalk from 'chalk';
import { execSync } from 'child_process';
import packageJson from '../../../package.json' with { type: 'json'};
import { ReleaseCheckResult, ReleaseInfo, PLATFORM_BINARIES, PlatformKey } from './types.js';
import { VersionComparator } from './version-comparator.js';

const RELEASE_URL = 'TODO';
const REQUEST_TIMEOUT = 30000;

export class ReleaseChecker {
    private static latestVersion: string = '';
    private static checkSuccessful: boolean = false;

    public static async startBackgroundCheck(): Promise<void> {
        try {
            this.latestVersion = await this.getLatestVersionForBackgroundCheck() || '';
            this.checkSuccessful = true;
        } catch {
            // Silent failure
        }
    }

    public static showUpdateNotificationIfAvailable(): void {
        try {
            if (this.checkSuccessful && this.latestVersion) {
                const currentVersion = this.getCurrentVersion();
                const isNewerVersion = VersionComparator.isNewer(this.latestVersion, currentVersion);

                if (isNewerVersion) {
                    console.log();
                    console.log(chalk.yellow('New version available: ') + chalk.gray(currentVersion) + ' → ' + chalk.green(this.latestVersion));
                    console.log('Run ' + chalk.cyan('srt update') + ' to install the latest version');
                }
            }
        } catch (error) {
            // Silent failure
        }
    }

    public static async getLatestVersionForBackgroundCheck(): Promise<string | null> {
        try {
            const platformKey = this.getPlatformBinaryKey();
            if (!platformKey) return null;

            const platformSuffix = this.getPlatformSuffix(platformKey);
            const latestFileName = await this.findLatestFileForPlatform(platformSuffix);

            if (!latestFileName) return null;

            const latestVersion = this.extractVersionFromFilename(latestFileName);
            return latestVersion;
        } catch (error) {
            return null;
        }
    }

    public static async getLatestRelease(): Promise<ReleaseCheckResult> {
        try {
            const currentVersion = this.getCurrentVersion();

            const platformKey = this.getPlatformBinaryKey();
            if (!platformKey) {
                return { status: 'up_to_date' };
            }

            const platformSuffix = this.getPlatformSuffix(platformKey);
            const latestFileName = await this.findLatestFileForPlatform(platformSuffix);

            if (!latestFileName) {
                return { status: 'up_to_date' };
            }

            const latestVersion = this.extractVersionFromFilename(latestFileName);
            if (!latestVersion) {
                return { status: 'up_to_date' };
            }

            if (!VersionComparator.isNewer(latestVersion, currentVersion)) {
                return { status: 'up_to_date' };
            }

            const downloadUrl = `TODO/${latestFileName}?download=true`;

            return {
                status: 'update_available',
                releaseInfo: {
                    version: latestVersion,
                    downloadUrl
                }
            };
        } catch (error) {
            return { status: 'up_to_date' };
        }
    }

    public static getCurrentVersion(): string {
        return packageJson.version;
    }

    public static getPlatformBinaryKey(): PlatformKey | null {
        const platform = process.platform;
        const arch = process.arch;

        if (platform === 'darwin') {
            if (arch === 'arm64') return 'darwin-arm64';
            if (arch === 'x64') return 'darwin-x64';
        } else if (platform === 'linux') {
            if (arch === 'x64') return 'linux-x64';
        } else if (platform === 'win32') {
            if (arch === 'x64') return 'win32-x64';
        }

        return null;
    }

    public static getPlatformSuffix(platformKey: PlatformKey): string {
        switch (platformKey) {
            case 'darwin-arm64': return 'macos-arm64.tar.gz';
            case 'darwin-x64': return 'macos-x64.tar.gz';
            case 'linux-x64': return 'linux-x64.tar.gz';
            case 'win32-x64': return 'windows-x64.zip';
        }
    }

    private static async findLatestFileForPlatform(platformSuffix: string): Promise<string | null> {
        try {
            const curlCommand = `curl -L "${RELEASE_URL}"`;
            const html = execSync(curlCommand, {
                encoding: 'utf8',
                timeout: REQUEST_TIMEOUT,
                stdio: ['ignore', 'pipe', 'ignore']
            });

            const fileMatches = html.match(/srt-cli-v[\d.]+-[^"<>]+?\.(tar\.gz|zip)/g);
            if (!fileMatches) return null;

            const platformFile = fileMatches.find(filename => filename.endsWith(platformSuffix));
            return platformFile || null;

        } catch (error) {
            return null;
        }
    }

    private static extractVersionFromFilename(filename: string): string | null {
        const versionMatch = filename.match(/srt-cli-v([\d.]+)-/);
        return versionMatch ? versionMatch[1] : null;
    }
}
