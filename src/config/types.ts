export interface PathUpdateStatus {
    status: 'SUCCESS' | 'INFO' | 'ERROR' | 'SKIPPED';
    needsRestart: boolean;
}

export interface PrerequisiteInstallStatus {
    status: 'SUCCESS' | 'ERROR' | 'SKIPPED';
    errors?: string[];
}
