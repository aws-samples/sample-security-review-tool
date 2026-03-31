import chalk from 'chalk';
import { Command } from 'commander';
import { confirm } from '@inquirer/prompts';
import { formatDistanceToNow } from 'date-fns';
import { handleError } from '../shared/error-handling/handle-error.js';
import { StatusCoordinator } from './coordinator.js';
import { BrowserOpener } from './browser-opener.js';

export class StatusCommand {
    public static register(program: Command): void {
        program
            .command('status')
            .description('Show SRT project status and issue summary')
            .option('-p, --path <project-path>', 'Project root folder path')
            .option('-a, --all', 'Show all issues (default shows only high priority)')
            .action(async (options): Promise<void> => {
                try {
                    await StatusCommand.execute(options);
                } catch (error) {
                    const errorMessage = error instanceof Error ? error.message : 'Unknown error during status check';
                    await handleError({
                        source: 'srt_status_command',
                        type: 'execution_error',
                        message: errorMessage,
                        context: {},
                        consoleMessage: 'Status check failed',
                        shouldThrow: true
                    });
                }
            });
    }

    public static async execute(options: any): Promise<void> {
        const projectRootFolderPath = options?.path || process.cwd();

        const reporter = await StatusCoordinator.create(projectRootFolderPath);
        const status = await reporter.getStatus({ showAll: options?.all ?? false });

        console.log('\n' + chalk.bold('SRT Status\n'));

        const lastScanDate = status.lastScanDate
            ? formatDistanceToNow(status.lastScanDate, { addSuffix: true })
            : 'Never';

        console.log(`License: ${chalk.blueBright(status.license)}`)
        console.log(`Last Scan: ${chalk.blueBright(lastScanDate)}`);

        console.log();
        console.log(`Open: ${chalk.redBright(status.openIssues)}`);
        console.log(`Reopened: ${chalk.yellowBright(status.reopenedIssues)}`);
        console.log(`Fixed: ${chalk.greenBright(status.fixedIssues)}`);
        console.log(`Suppressed: ${chalk.blueBright(status.suppressedIssues)}`);

        console.log();

        const issuesNeedingAttention = status.openIssues + status.reopenedIssues;
        if (issuesNeedingAttention > 0) {
            console.log(chalk.yellow(`${issuesNeedingAttention} issue${issuesNeedingAttention === 1 ? '' : 's'} need attention`));
            console.log(`Progress: ${status.completionRate}% complete`);
        } else {
            console.log(chalk.green('No open issues'));
        }

        console.log();

        if (status.dashboardPath && !options?.yes) {
            await StatusCommand.promptOpenDashboard(status.dashboardPath);
        }
    }

    private static async promptOpenDashboard(dashboardPath: string): Promise<void> {
        try {
            const openDashboard = await confirm({
                message: 'Open dashboard in browser?',
                default: true
            });

            if (openDashboard) {
                const browserOpener = new BrowserOpener();
                const success = await browserOpener.open(dashboardPath);
                if (!success) {
                    console.log(chalk.yellow(`Dashboard available at: ${dashboardPath}`));
                }
            }
        } catch {
            // User cancelled prompt (Ctrl+C)
        }
    }
}
