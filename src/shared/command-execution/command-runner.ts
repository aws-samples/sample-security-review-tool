import { exec } from "child_process";
import { ProcessManager } from "./process-manager.js";

export class CommandRunner {
    public async exec(command: string, cwd: string, suppressErrorLogging: boolean = false, envOverrides?: Record<string, string>): Promise<string> {
        return new Promise((resolve, reject) => {
            const processManager = ProcessManager.getInstance();
            const processId = `${command.substring(0, 30)}...${Date.now()}`;

            const env = { ...process.env, PYTHONUTF8: '1', ...envOverrides };
            const childProcess = exec(command, { cwd, env }, (error, stdout, stderr) => {
                processManager.unregisterOperation(processId);

                if (error) {
                    if (!processManager.wasOperationTerminated(processId)) {
                        if (!suppressErrorLogging) {
                            // Error logging removed per requirements
                        }
                        reject(error);
                    }
                    return;
                }

                resolve(stdout);
            });

            processManager.registerProcess(processId, childProcess, `Command: ${command}`);
        });
    }
}
