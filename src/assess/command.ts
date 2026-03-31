import { Command, Option } from "commander";
import chalk from 'chalk';
import * as path from 'path';
import { input, select } from '@inquirer/prompts';
import { Licenses } from "./licensing/licenses.js";
import { ReleaseChecker } from '../update/release/release-checker.js';
import { StatusCommand } from "../status/command.js";
import { ui } from '../shared/ui.js';
import { AssessCoordinator } from './coordinator.js';
import { AssessHelpers } from "./helpers.js";
import { ScannerSetup } from '../config/scanner/scanner-setup.js';

export class AssessCommand {
    public static register(program: Command): void {
        program
            .command('assess', { isDefault: true })
            .description('Perform an SRT assessment')
            .option('-p, --path <project-path>', 'Project root folder path')
            .addOption(new Option('-l, --license <license-type>', 'Software license type').choices(['aws', 'mit', 'apache']))
            .option('--no-license-update', 'Skip license header updates')
            .option('--no-diagrams', 'Skip diagram generation')
            .option('--no-threat-models', 'Skip threat model generation')
            .option('--xlsx', 'Generate Excel report in addition to dashboard')
            .option('--cdk-out <path>', 'Path to pre-existing CDK output directory (skips CDK synth). Can be specified multiple times.', (value: string, previous: string[]) => previous.concat([value]), [] as string[])
            .option('-y, --yes', 'Use defaults for any options not specified on command line')
            .version(ReleaseChecker.getCurrentVersion())
            .action(async (options) => {
                try {
                    AssessCommand.displayWelcomeMessage();
                    await AssessCommand.execute(options);
                } catch (error) {
                    if (error instanceof Error && error.name === 'ExitPromptError') {
                        console.log('SRT cancelled.');
                    } else {
                        const message = error instanceof Error ? error.message : String(error);
                        console.error(chalk.red(`\n${ui.error(`Assessment failed: ${message}`)}`));
                        process.exit(1);
                    }
                }
            });
    }

    private static displayWelcomeMessage(): void {
        const version = ReleaseChecker.getCurrentVersion();
        console.log('\n' + chalk.blue.bold('┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓'));
        console.log(chalk.blue.bold('┃                                                  ┃'));
        console.log(chalk.blue.bold('┃   ') + chalk.white.bold('🔒 SRT - Security Review Tool ') + chalk.green.bold(`v${version}`) + chalk.blue.bold('    ┃'));
        console.log(chalk.blue.bold('┃                                                  ┃'));
        console.log(chalk.blue.bold('┃   ') + chalk.white('Security assessment for AWS infrastructure     ') + chalk.blue.bold('┃'));
        console.log(chalk.blue.bold('┃   ') + chalk.white('templates, configs, and deployment artifacts   ') + chalk.blue.bold('┃'));
        console.log(chalk.blue.bold('┃                                                  ┃'));
        console.log(chalk.blue.bold('┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛') + '\n');
    }

    private static async execute(options: any): Promise<void> {
        const scannerSetup = new ScannerSetup();
        const allInstalled = await scannerSetup.checkAllInstalled();

        if (!allInstalled) {
            console.error(chalk.red(`\n${ui.error('Prerequisites not installed.')}`));
            console.log(chalk.yellow("Run 'srt config' first to install prerequisites.\n"));
            process.exit(1);
        }

        const projectRootFolderPath = options?.path || process.cwd();
        const cdkOutPaths = options?.cdkOut?.length > 0
            ? options.cdkOut.map((p: string) => path.resolve(p))
            : undefined;
        const license = await AssessCommand.getLicense(projectRootFolderPath, options);
        const updateLicenses = await AssessCommand.shouldUpdateLicenseHeaders(projectRootFolderPath, options);

        const coordinator = new AssessCoordinator(projectRootFolderPath, (progress) => {
            console.log(chalk.white(progress));
        }, cdkOutPaths);

        console.log();

        await coordinator.assess(
            license,
            updateLicenses,
            options.diagrams,
            options.threatModels,
            options.xlsx || false
        );

        console.log(`\n${ui.success(chalk.green('SRT complete!'))}`);

        await StatusCommand.execute({ path: projectRootFolderPath, yes: options?.yes });
    }

    private static async getLicense(projectRootFolderPath: string, options: any): Promise<string> {
        if (options?.license) {
            return options.license.toUpperCase();
        }

        if (options?.yes) {
            return Licenses.getDefault().value;
        }

        const projectLicense = await AssessHelpers.getProjectLicense(projectRootFolderPath);

        if (!projectLicense) {
            console.log('\nSRT requires all code files to have a license header. Please select the appropriate license for your project. If you are unsure which license to use select \'AWS\'.\n');

            return await select({
                message: 'Select a license type:',
                choices: Licenses.getAll(),
                default: Licenses.getDefault().value
            });
        }

        return projectLicense;
    }

    private static async shouldUpdateLicenseHeaders(projectRootFolderPath: string, options: any): Promise<boolean> {
        if (options?.licenseUpdate === false) return false;

        const headerCheck = await AssessHelpers.checkForExistingLicenseHeaders(projectRootFolderPath);

        if (headerCheck.hasExistingHeaders && !options?.yes) {
            console.log(chalk.yellowBright(`\n!  Found 1 or more code files with existing license headers\n`));

            const licenseAction = await select({
                message: 'How would you like to proceed?',
                choices: ['Keep existing license headers (no changes will be made)', 'Replace existing license headers', 'Exit without making changes'],
                default: 'Keep existing license headers (no changes will be made)'
            });

            if (licenseAction === 'Exit without making changes') {
                console.log('✗ SRT cancelled.');
                process.exit(0);
            }

            return licenseAction === 'Replace existing license headers';
        }

        return true;
    }
}
