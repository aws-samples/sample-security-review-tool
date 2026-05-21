export interface CodeScanResult {
    semgrepSummaryPath: string;
    banditSummaryPath: string | null;
    syftSummaryPath: string;
}

export interface IaCTemplateResult {
    iacType: 'CloudFormation' | 'Terraform';
    name: string;
    checkovSummaryPath: string | null;
    securityMatrixPath: string | null;
    diagramPath: string | null;
    threatModelPath: string | null;
}

export interface LicenseHeaderCheckResult {
    hasExistingHeaders: boolean;
    fileCount: number;
}
