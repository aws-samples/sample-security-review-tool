export interface DownloadResult {
    success: boolean;
    binaryPath?: string;
    error?: string;
}

export interface InstallResult {
    success: boolean;
    error?: string;
}

export interface TestResult {
    success: boolean;
    error?: string;
}
