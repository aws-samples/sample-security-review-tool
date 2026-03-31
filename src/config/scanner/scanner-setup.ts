import { ScannerToolManager } from '../../shared/scanner-tools/scanner-tool-manager.js';
import { ScanTool } from '../../shared/scanner-tools/types.js';
import { ScannerSetupResult } from './types.js';
import { ui } from '../../shared/ui.js';

export class ScannerSetup {
    private readonly toolManager = new ScannerToolManager();

    constructor(private readonly onProgress: (progress: string) => void = () => { }) { }

    public async installMissingScanners(forceReinstall: boolean = false): Promise<ScannerSetupResult> {
        const errors: string[] = [];
        const scannersToInstall = forceReinstall
            ? ScannerToolManager.getAllScanTools()
            : await this.getMissingScanners();

        if (scannersToInstall.length === 0) {
            return { success: true, errors: [], noneInstalled: true };
        }

        const spin = ui.spinner('Installing prerequisites...').start();

        try {
            await this.toolManager.ensureVenvExists();
        } catch (error) {
            const errorMsg = error instanceof Error ? error.message : 'Failed to create virtual environment';
            errors.push(errorMsg);
            spin.fail('Failed to install prerequisites');
            return { success: false, errors };
        }

        const failed: string[] = [];

        for (const scanner of scannersToInstall) {
            const scannerName = this.getScannerDisplayName(scanner);

            try {
                spin.text = `Installing ${scannerName}...`;
                await this.toolManager.installTool(scanner);
            } catch (error) {
                const errorMsg = error instanceof Error ? error.message : `Failed to install ${scannerName}`;
                errors.push(errorMsg);
                failed.push(scannerName);
            }
        }

        if (failed.length > 0) {
            spin.fail(`Prerequisites installed with errors: ${failed.join(', ')} failed`);
        } else {
            spin.succeed('Prerequisites installed');
        }

        return { success: errors.length === 0, errors };
    }

    public async getMissingScanners(): Promise<ScanTool[]> {
        const allScanners = ScannerToolManager.getAllScanTools();
        const missing: ScanTool[] = [];

        for (const scanner of allScanners) {
            const installed = await this.toolManager.isToolInstalled(scanner);
            if (!installed) missing.push(scanner);
        }

        return missing;
    }

    public async checkAllInstalled(): Promise<boolean> {
        const scanners = ScannerToolManager.getAllScanTools();

        for (const scanner of scanners) {
            const installed = await this.toolManager.isToolInstalled(scanner);
            if (!installed) return false;
        }

        return true;
    }

    private getScannerDisplayName(scanner: ScanTool): string {
        switch (scanner) {
            case ScanTool.CHECKOV: return 'Checkov';
            case ScanTool.SEMGREP: return 'Semgrep';
            case ScanTool.BANDIT: return 'Bandit';
            case ScanTool.SYFT: return 'Syft';
            case ScanTool.JUPYTER: return 'Jupyter';
            default: return scanner;
        }
    }
}
