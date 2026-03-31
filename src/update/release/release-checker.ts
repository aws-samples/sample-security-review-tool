import chalk from 'chalk';
import { execSync } from 'child_process';
import packageJson from '../../../package.json' with { type: 'json'};
import { ReleaseCheckResult, ReleaseInfo, PlatformKey } from './types.js';
import { VersionComparator } from './version-comparator.js';

const GITHUB_API_URL = 'https://api.github.com/repos/aws-samples/sample-security-review-tool/releases/latest';
const RELEASES_PAGE_URL = 'https://github.com/aws-samples/sample-security-review-tool/releases';
const REQUEST_TIMEOUT = 30000;

interface GitHubAsset {
    name: string;
    browser_download_url: string;
}

interface GitHubRelease {
    tag_name: string;
    assets: GitHubAsset[];
}

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
            const result = this.fetchLatestRelease();
            return result?.version ?? null;
        } catch (error) {
            return null;
        }
    }

    public static async getLatestRelease(): Promise<ReleaseCheckResult> {
        try {
            const currentVersion = this.getCurrentVersion();
            const result = this.fetchLatestRelease();

            if (!result) {
                return { status: 'up_to_date' };
            }

            if (!VersionComparator.isNewer(result.version, currentVersion)) {
                return { status: 'up_to_date' };
            }

            return {
                status: 'update_available',
                releaseInfo: {
                    version: result.version,
                    downloadUrl: result.downloadUrl
                }
            };
        } catch (error) {
            return { status: 'up_to_date' };
        }
    }

    public static getCurrentVersion(): string {
        return packageJson.version;
    }

    public static getReleasesPageUrl(): string {
        return RELEASES_PAGE_URL;
    }

    public static getPlatformBinaryKey(): PlatformKey | null {
        const platform = process.platform;
        const arch = process.arch;

        if (platform === 'darwin') {
            if (arch === 'arm64') return 'darwin-arm64';
            if (arch === 'x64') return 'darwin-x64';
        } else if (platform === 'linux') {
            if (arch === 'x64') return 'linux-x64';
            if (arch === 'arm64') return 'linux-arm64';
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
            case 'linux-arm64': return 'linux-arm64.tar.gz';
            case 'win32-x64': return 'windows-x64.zip';
        }
    }

    private static fetchLatestRelease(): { version: string; downloadUrl: string } | null {
        try {
            const platformKey = this.getPlatformBinaryKey();
            if (!platformKey) return null;

            const json = execSync(`curl -s -L -H "Accept: application/vnd.github+json" "${GITHUB_API_URL}"`, {
                encoding: 'utf8',
                timeout: REQUEST_TIMEOUT,
                stdio: ['ignore', 'pipe', 'ignore']
            });

            const release: GitHubRelease = JSON.parse(json);
            const version = release.tag_name.replace(/^v/, '');
            const platformSuffix = this.getPlatformSuffix(platformKey);
            const asset = release.assets.find(a => a.name.endsWith(platformSuffix));

            if (!asset) return null;

            return { version, downloadUrl: asset.browser_download_url };
        } catch {
            return null;
        }
    }
}
