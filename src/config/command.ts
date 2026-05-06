import chalk from 'chalk';
import { select, confirm } from '@inquirer/prompts';
import { Command } from 'commander';
import { handleError } from '../shared/error-handling/handle-error.js';
import { ConfigCoordinator } from './coordinator.js';
import { ValidationResult } from './aws/types.js';
import { PathUpdateStatus } from './types.js';

import { ui } from '../shared/ui.js';

export class ConfigCommand {
    static register(program: Command): void {
        program
            .command('config')
            .description('Configure AWS settings for SRT')
            .action(async (): Promise<void> => {
                try {
                    await ConfigCommand.execute();
                } catch (error) {
                    if (error instanceof Error && error.name === 'ExitPromptError') {
                        console.log('Configuration cancelled.');
                    } else {
                        const errorMessage = error instanceof Error ? error.message : 'Unknown error during configuration';
                        await handleError({
                            source: 'srt_config_command',
                            type: 'execution_error',
                            message: errorMessage,
                            context: {},
                            consoleMessage: 'Configuration failed',
                            shouldThrow: true
                        });
                    }
                }
            });
    }

    private static async execute(): Promise<void> {
        console.log('\n' + ui.header('SRT Configuration Setup'));
        console.log(ui.dimmed('Configure your AWS settings for the Deliverable Security Review tool.\n'));

        const coordinator = new ConfigCoordinator((progress) => {
            console.log(chalk.white(progress));
        });

        const awsProfiles = await coordinator.discoverProfiles();

        if (awsProfiles.length === 0) {
            console.error(chalk.red(ui.error('No AWS profiles found!')));
            console.log(chalk.yellow('Please ensure you have AWS credentials configured.'));
            console.log(chalk.gray('See: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html'));
            console.log();
            process.exit(1);
        }

        const existingConfig = await coordinator.loadExistingConfig();
        const defaultProfile = coordinator.determineDefaultProfile(awsProfiles);

        const profileChoices = awsProfiles.map(profile => ({
            name: `${profile.name}${profile.isDefault ? ' (default)' : ''} (${profile.region})`,
            value: profile.name
        }));

        const awsProfile = await select({
            message: 'Select AWS Profile:',
            choices: profileChoices,
            default: existingConfig?.AWS_PROFILE || defaultProfile?.name
        });

        const selectedProfile = awsProfiles.find(p => p.name === awsProfile);
        const awsRegion = selectedProfile!.region!;

        const pathCheck = coordinator.checkPath();
        let pathUpdateStatus: PathUpdateStatus;

        if (pathCheck.isInPath) {
            pathUpdateStatus = {
                status: 'INFO',
                needsRestart: false
            };
        } else {
            const updatePath = await confirm({
                message: 'Would you like to add SRT to your PATH? This enables you to run srt from any directory',
                default: true
            });

            if (updatePath) {
                const result = await coordinator.updatePath();
                pathUpdateStatus = {
                    status: result.success ? 'SUCCESS' : 'ERROR',
                    needsRestart: result.needsRestart
                };
            } else {
                pathUpdateStatus = {
                    status: 'SKIPPED',
                    needsRestart: false
                };
            }
        }

        const telemetryEnabled = await confirm({
            message: 'Allow anonymous usage telemetry? (helps improve SRT)',
            default: true
        });

        const validationSpin = ui.spinner('Validating credentials...').start();
        const validationResult = await coordinator.validateAndSave(awsProfile as string, awsRegion, telemetryEnabled);

        validationSpin.succeed('AWS Region: ' + awsRegion);

        if (validationResult.modelAccessible) {
            console.log(ui.success('Bedrock Model: ') + 'Accessible');
        } else {
            console.log(ui.error('Bedrock Model: ') + 'Not accessible');
        }

        if (validationResult.validCredentials) {
            console.log(ui.success('AWS Profile: ') + (awsProfile as string) + (validationResult.credentialSource ? ui.dimmed(` (${validationResult.credentialSource})`) : ''));
        } else {
            console.log(ui.error('AWS Profile: ') + (awsProfile as string));
        }

        if (pathUpdateStatus.status === 'SUCCESS') {
            console.log(ui.success('PATH: ') + 'Enabled ' + ui.dimmed('(restart required)'));
        } else if (pathUpdateStatus.status === 'INFO') {
            console.log(ui.success('PATH: ') + 'Enabled');
        } else if (pathUpdateStatus.status === 'SKIPPED') {
            console.log(ui.hint('PATH: ') + 'Disabled');
        } else if (pathUpdateStatus.status === 'ERROR') {
            console.log(ui.error('PATH: ') + 'Failed');
        }

        if (telemetryEnabled) {
            console.log(ui.success('Telemetry: ') + 'Enabled');
        } else {
            console.log(ui.hint('Telemetry: ') + 'Disabled');
        }

        if (validationResult.errors.length > 0) {
            validationResult.errors.forEach(error => console.log(chalk.red('\n' + error)));
        }

        if (!validationResult.isValid) {
            console.log(chalk.red('\n' + ui.error('Configuration cannot be saved. Please address the issues above and try again.')));
            return;
        }

        console.log('\n' + ui.success('Configuration saved!'));

        if (pathUpdateStatus.needsRestart) {
            ConfigCommand.displayRestartInstructions(coordinator);
        }

        console.log();
    }

    private static displayRestartInstructions(coordinator: ConfigCoordinator): void {
        console.log('\n' + ui.warning('Restart Required'));

        const instructions = coordinator.getRestartInstructions();
        instructions.forEach((line: string) => console.log(chalk.yellow(line)));
    }
}
