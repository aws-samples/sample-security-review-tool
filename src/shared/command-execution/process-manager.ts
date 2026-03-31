import { ChildProcess } from 'child_process';
import { SrtLogger } from '../logging/srt-logger.js';

type BackgroundOperation = {
  type: 'process' | 'async';
  process?: ChildProcess;
  abortController?: AbortController;
  description: string;
  isBeingTerminated?: boolean;
};

export class ProcessManager {
  private static instance: ProcessManager;
  private operations: Map<string, BackgroundOperation>;
  private isShuttingDown: boolean = false;
  private terminatedOperationIds: Set<string> = new Set();

  private constructor() {
    this.operations = new Map();
  }

  public static getInstance(): ProcessManager {
    if (!ProcessManager.instance) {
      ProcessManager.instance = new ProcessManager();
    }
    return ProcessManager.instance;
  }

  public registerProcess(id: string, process: ChildProcess, description: string): void {
    this.operations.set(id, {
      type: 'process',
      process,
      description
    });
  }

  public registerAsyncOperation(id: string, abortController: AbortController, description: string): void {
    this.operations.set(id, {
      type: 'async',
      abortController,
      description
    });
  }

  public unregisterOperation(id: string): void {
    if (this.operations.has(id)) {
      this.operations.delete(id);
    }
  }

  public wasOperationTerminated(id: string): boolean {
    return this.terminatedOperationIds.has(id);
  }

  public terminateAll(): void {
    if (this.isShuttingDown) {
      return;
    }

    this.isShuttingDown = true;

    for (const [id, operation] of this.operations.entries()) {
      try {
        operation.isBeingTerminated = true;
        this.terminatedOperationIds.add(id);

        if (operation.type === 'process' && operation.process && !operation.process.killed) {
          operation.process.kill();
        } else if (operation.type === 'async' && operation.abortController) {
          operation.abortController.abort();
        }
      } catch (error) {
        SrtLogger.logError('Failed to terminate operation', error as Error, { id });
      }
    }

    setTimeout(() => {
      const remainingOperations = this.operations.size;
      if (remainingOperations > 0) {
        this.operations.clear();
      }

      this.isShuttingDown = false;
    }, 2000);
  }

  public getRunningOperationCount(): number {
    return this.operations.size;
  }
}
