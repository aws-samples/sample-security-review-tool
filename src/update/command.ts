import chalk from 'chalk';
import { Command } from 'commander';
import { UpdateCoordinator } from './coordinator.js';
import { ReleaseChecker } from './release/release-checker.js';
import { PLATFORM_BINARIES, PlatformKey } from './release/types.js';
import { handleError } from '../shared/error-handling/handle-error.js';

export class UpdateCommand {
    public static register(program: Command): void {
        program
            .command('update')
            .description('Update to the latest version of SRT')
            .action(async (): Promise<void> => {
                try {
                    await UpdateCommand.execute();
                } catch (error) {
                    const errorMessage = error instanceof Error ? error.message : 'Unknown error during update';
                    await handleError({
                        source: 'srt_update_command',
                        type: 'execution_error',
                        message: errorMessage,
                        context: {},
                        consoleMessage: 'Update failed',
                        shouldThrow: true
                    });
                }
            });
    }

    public static async execute(): Promise<void> {
        console.log(chalk.blue('SRT Update'));
        console.log();

        const orchestrator = new UpdateCoordinator();
        const currentVersion = orchestrator.getCurrentVersion();

        console.log(chalk.gray(`Current version: ${currentVersion}`));
        console.log();

        console.log('Checking for updates...');
        const result = await orchestrator.performUpdate();

        if (result.status === 'up_to_date') {
            console.log(chalk.green('You are running the latest version'));
            console.log();
            console.log(chalk.gray('To check for updates manually:'));
            UpdateCommand.showManualDownloadInstructions();
            return;
        }

        if (result.status === 'download_failed') {
            console.log(chalk.yellow('Download failed. Manual download required:'));
            console.log();
            UpdateCommand.showManualDownloadInstructions();
            return;
        }

        if (result.status === 'install_failed') {
            console.log(chalk.yellow('Installation failed. Manual download required:'));
            console.log();
            UpdateCommand.showManualDownloadInstructions();
            return;
        }

        if (result.status === 'test_failed') {
            console.log(chalk.red('New binary failed tests, rolling back...'));
            console.log(chalk.yellow('Update failed. Manual download required:'));
            console.log();
            UpdateCommand.showManualDownloadInstructions();
            return;
        }

        console.log(chalk.green(`Successfully updated to version ${result.newVersion}!`));
    }

    private static showManualDownloadInstructions(): void {
        //TODO Log out the releases URL
        console.log();

        const platformKey = ReleaseChecker.getPlatformBinaryKey();
        if (platformKey) {
            const fileSuffix = UpdateCommand.getFileSuffix(platformKey);
            console.log(chalk.gray(`Download the file that ends with: ${fileSuffix}`));
        } else {
            console.log(chalk.red('Unable to determine your platform. Please check the releases page for available downloads.'));
        }
    }

    private static getFileSuffix(platformKey: PlatformKey): string {
        return ReleaseChecker.getPlatformSuffix(platformKey);
    }
}
