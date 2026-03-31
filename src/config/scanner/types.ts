// export interface ScannerInstallProgress {
//     phase: 'venv' | 'scanner';
//     scanner?: string;
//     status: 'starting' | 'complete' | 'error';
// }

export interface ScannerSetupResult {
    success: boolean;
    errors: string[];
    noneInstalled?: boolean;
}
