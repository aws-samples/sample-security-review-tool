import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

export class BrowserOpener {
    public async open(filePath: string): Promise<boolean> {
        try {
            const command = this.getCommand(filePath);
            await execAsync(command);
            return true;
        } catch {
            return false;
        }
    }

    private getCommand(filePath: string): string {
        const escapedPath = filePath.replace(/"/g, '\\"');

        switch (process.platform) {
            case 'win32':
                return `start "" "${escapedPath}"`;
            case 'darwin':
                return `open "${escapedPath}"`;
            default:
                return `xdg-open "${escapedPath}"`;
        }
    }
}
