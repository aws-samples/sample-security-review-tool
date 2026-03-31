import { CommandRunner } from '../command-execution/command-runner.js';

export class CdkToolManager {
    private readonly commandRunner: CommandRunner;

    constructor() {
        this.commandRunner = new CommandRunner();
    }

    public async isCdkInstalled(): Promise<boolean> {
        const checkCommand = process.platform === 'win32' ? 'where cdk' : 'which cdk';
        try {
            await this.commandRunner.exec(checkCommand, process.cwd(), true);
            return true;
        } catch {
            return false;
        }
    }

    public async installCdk(workingDirectory: string): Promise<void> {
        await this.commandRunner.exec('npm install -g aws-cdk', workingDirectory);
    }
}