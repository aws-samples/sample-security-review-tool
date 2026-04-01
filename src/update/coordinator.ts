import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs';
import { ReleaseChecker } from './release/release-checker.js';
import { BinaryDownloader } from './binary/binary-downloader.js';
import { BinaryInstaller } from './binary/binary-installer.js';
import { ReleaseCheckResult } from './release/types.js';
import { AppPaths } from '../shared/app-config/app-paths.js';
import { SrtLogger } from '../shared/logging/srt-logger.js';
import { PostHogClient } from '../shared/analytics/posthog-client.js';
import { AppConfig } from '../shared/app-config/app-config.js';

export interface UpdateResult {
    status: 'success' | 'up_to_date' | 'download_failed' | 'install_failed' | 'test_failed';
    newVersion?: string;
    error?: string;
}

export class UpdateCoordinator {
    public async checkForUpdate(): Promise<ReleaseCheckResult> {
        const result = await ReleaseChecker.getLatestRelease();
        this.captureUpdateChecked(result);
        return result;
    }

    private captureUpdateChecked(result: ReleaseCheckResult): void {
        const installationId = AppConfig.getInstallationId();
        if (!installationId || !AppConfig.isTelemetryEnabled()) return;

        PostHogClient.initialize(installationId);
        PostHogClient.captureUpdateChecked({
            current_version: ReleaseChecker.getCurrentVersion(),
            update_available: result.status === 'update_available'
        });
    }

    public async performUpdate(): Promise<UpdateResult> {
        const releaseCheckResult = await ReleaseChecker.getLatestRelease();

        if (releaseCheckResult.status === 'up_to_date') {
            return { status: 'up_to_date' };
        }

        const releaseInfo = releaseCheckResult.releaseInfo;
        const tempDir = os.tmpdir();
        const extension = releaseInfo.downloadUrl.includes('.tar.gz') ? '.tar.gz' : '.zip';
        const tempBinaryPath = path.join(tempDir, `srt-update-${releaseInfo.version}${extension}`);

        const downloadResult = await BinaryDownloader.download(
            releaseInfo.downloadUrl,
            tempBinaryPath
        );

        if (!downloadResult.success) {
            SrtLogger.logError('Download failed', new Error(downloadResult.error || 'Unknown'), { tempBinaryPath });
            return { status: 'download_failed', error: downloadResult.error };
        }

        const currentBinaryPath = path.join(AppPaths.getAppDir(), path.basename(process.execPath));
        const installResult = BinaryInstaller.install(tempBinaryPath, currentBinaryPath);

        if (!installResult.success) {
            SrtLogger.logError('Installation failed', new Error(installResult.error || 'Unknown'), { currentBinaryPath });
            if (fs.existsSync(tempBinaryPath)) {
                fs.unlinkSync(tempBinaryPath);
            }
            return { status: 'install_failed', error: installResult.error };
        }

        const testResult = BinaryInstaller.test(currentBinaryPath);

        if (!testResult.success) {
            BinaryInstaller.rollback(currentBinaryPath);
            return { status: 'test_failed', error: testResult.error };
        }

        return { status: 'success', newVersion: releaseInfo.version };
    }

    public getCurrentVersion(): string {
        return ReleaseChecker.getCurrentVersion();
    }
}
