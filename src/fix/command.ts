import { Command } from "commander";
import { confirm, input, select, Separator } from '@inquirer/prompts';
import chalk from 'chalk';
import ora from "ora";
import { handleError } from '../shared/error-handling/handle-error.js';
import { FixCoordinator } from './coordinator.js';
import { DiffFormatter } from './code-manipulation/diff-formatter.js';
import { Fix } from './types.js';

export class FixCommand {
    public static register(program: Command): void {
        program
            .command('fix', { hidden: true })
            .description('Fix issues in the SRT project')
            .option('-p, --path <project-path>', 'Project root folder path')
            .option('-e, --experimental', 'Enable experimental features')
            .action(async (options): Promise<void> => {
                try {
                    const projectRootFolderPath = options?.path || process.cwd();

                    if (options.experimental) {
                        console.log(chalk.yellowBright('Experimental features enabled: \'Generate fix\' option is available.\n'));
                    }

                    const coordinator = await FixCoordinator.create(projectRootFolderPath, () => {});
                    const issues = await coordinator.getIssues("high", "open");

                    console.log();

                    const acknowledgement = await confirm({
                        message: `This tool uses AI to suggest code fixes, which may introduce errors or unintended changes. Please commit your current work to git before proceeding so you can easily revert if needed. Do you want to continue?`
                    });

                    // This is a workaround for an issue with Bun+inquirer.js where it doesn't enable input for subsequent prompts
                    process.stdin.setRawMode(true);

                    if (!acknowledgement) {
                        return;
                    }

                    for (const issue of issues) {
                        console.log();

                        const filePath = await coordinator.getCodeFilePath(issue);

                        console.log(`${chalk.blueBright('Issue:')} ${issue.issue}`);
                        if (issue.resourceType) console.log(`${chalk.blueBright('Resource Type:')} ${issue.resourceType}`);
                        if (issue.resourceName) console.log(`${chalk.blueBright('Resource Name:')} ${issue.resourceName}`);
                        if (issue.path) console.log(`${chalk.blueBright('File:')} ${filePath}`);
                        if (issue.line) console.log(`${chalk.blueBright('Line:')} ${issue.line}`);
                        if (issue.fix) console.log(`${chalk.blueBright('Fix:')} ${issue.fix}`);

                        const choices = [
                            { name: 'Suppress this finding', value: 'dontfix' },
                            { name: 'Skip for now', value: 'skipped' },
                            { name: 'Exit', value: 'exit' }
                        ];

                        if (options.experimental) {
                            choices.unshift({ name: 'Generate fix', value: 'generate' });
                        }

                        let issueHandled = false;
                        while (!issueHandled) {
                            console.log();

                            const actionAnswer = await select({
                                message: 'Choose an action:',
                                choices: choices,
                                default: 'ignored'
                            });

                            // This is a workaround for an issue with Bun+inquirer.js where it doesn't enable input for subsequent prompts
                            process.stdin.setRawMode(true);

                            if (actionAnswer === 'exit') {
                                return;
                            }

                            if (actionAnswer === 'skipped') {
                                console.log(chalk.yellowBright('Issue has been skipped for now.'));
                                issueHandled = true;
                                continue;
                            }

                            if (actionAnswer === 'dontfix') {
                                const suppressionResult = await FixCommand.promptSuppressionReason();

                                if ('action' in suppressionResult) {
                                    continue;
                                }

                                await coordinator.suppressIssue(issue, suppressionResult.reason);
                                console.log(chalk.blueBright('Issue has been suppressed.'));
                                issueHandled = true;
                                continue;
                            }

                            if (actionAnswer === 'generate') {
                                console.log();
                                const spinner = ora('Generating fix...').start();
                                const fix = await coordinator.generateFix(issue);
                                spinner.stop();

                                if (!fix) {
                                    console.log(chalk.yellowBright('Could not generate fix.'));
                                    continue;
                                }

                                FixCommand.showDiff(fix);

                                let fixHandled = false;
                                while (!fixHandled) {
                                    console.log();

                                    const applyAnswer = await select({
                                        message: 'Choose an action:',
                                        choices: [
                                            { name: 'Apply fix', value: 'apply' },
                                            { name: 'Suppress this finding', value: 'suppress' },
                                            { name: 'Skip for now', value: 'skip' },
                                            { name: 'Exit', value: 'exit' }
                                        ]
                                    });
                                    process.stdin.setRawMode(true);

                                    if (applyAnswer === 'exit') {
                                        return;
                                    }

                                    if (applyAnswer === 'apply') {
                                        await coordinator.applyFix(issue, fix);
                                        console.log(chalk.greenBright('Issue has been fixed.'));
                                        fixHandled = true;
                                        issueHandled = true;
                                    } else if (applyAnswer === 'suppress') {
                                        const suppressionResult = await FixCommand.promptSuppressionReason();

                                        if ('action' in suppressionResult) {
                                            continue;
                                        }

                                        await coordinator.suppressIssue(issue, suppressionResult.reason);
                                        console.log(chalk.blueBright('Issue has been suppressed.'));
                                        fixHandled = true;
                                        issueHandled = true;
                                    } else if (applyAnswer === 'skip') {
                                        console.log(chalk.yellowBright('Issue has been skipped for now.'));
                                        fixHandled = true;
                                        issueHandled = true;
                                    }
                                }
                            }
                        }
                    }
                } catch (error) {
                    if (error instanceof Error && error.name === 'ExitPromptError') {
                        console.log('Exiting issue fixer.');
                    } else {
                        const errorMessage = error instanceof Error ? error.message : 'Unknown error during fix';
                        await handleError({
                            source: 'srt_fix_command',
                            type: 'execution_error',
                            message: errorMessage,
                            context: { options },
                            consoleMessage: 'Fix operation failed',
                            shouldThrow: true
                        });
                    }
                }
            });
    }

    private static showDiff(fix: Fix): void {
        const diffFormatter = new DiffFormatter();
        const changesByFile = FixCommand.groupChangesByFile(fix.changes);

        for (const [filePath, changes] of changesByFile.entries()) {
            console.log(chalk.blueBright(`File: ${filePath}`));
            console.log();

            for (const change of changes) {
                const formattedLines = diffFormatter.formatDiff(
                    change.startingLineNumber,
                    change.original,
                    change.updated
                );
                formattedLines.forEach(line => console.log(line));
                console.log();
            }
        }
    }

    private static groupChangesByFile(changes: Fix['changes']): Map<string, Fix['changes']> {
        const grouped = new Map<string, Fix['changes']>();
        for (const change of changes) {
            if (!grouped.has(change.filePath)) {
                grouped.set(change.filePath, []);
            }
            grouped.get(change.filePath)!.push(change);
        }
        return grouped;
    }

    private static async promptSuppressionReason(): Promise<{ reason: string } | { action: 'back' }> {
        while (true) {
            const answer = await select({
                message: 'Select reason for suppression:',
                choices: [
                    { name: 'This is a false-positive', value: 'This is a false-positive' },
                    { name: 'This is not required/permitted by the customer', value: 'This is not required/permitted by the customer' },
                    { name: 'Other', value: 'Other' },
                    new Separator(),
                    { name: 'Go back', value: 'back' }
                ]
            });
            process.stdin.setRawMode(true);

            if (answer === 'back') {
                return { action: 'back' };
            }

            if (answer === 'Other') {
                const ac = new AbortController();
                const onKeypress = (_input: Buffer, key: { name: string }) => {
                    if (key?.name === 'escape') {
                        ac.abort();
                    }
                };
                process.stdin.on('keypress', onKeypress);

                try {
                    const customReason = await input({
                        message: 'Enter reason for suppression (Esc to cancel):',
                        validate: (value) => value.trim() ? true : 'Reason cannot be empty'
                    }, { signal: ac.signal });
                    process.stdin.removeListener('keypress', onKeypress);
                    process.stdin.setRawMode(true);

                    return { reason: customReason.trim() };
                } catch (error) {
                    process.stdin.removeListener('keypress', onKeypress);
                    if (error instanceof Error && (error.name === 'AbortPromptError' || error.name === 'ExitPromptError')) {
                        process.stdin.setRawMode(true);
                        continue;
                    }
                    throw error;
                }
            }

            return { reason: answer };
        }
    }
}
