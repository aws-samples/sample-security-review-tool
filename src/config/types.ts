export interface PathUpdateStatus {
    status: 'SUCCESS' | 'INFO' | 'ERROR' | 'SKIPPED';
    needsRestart: boolean;
}
