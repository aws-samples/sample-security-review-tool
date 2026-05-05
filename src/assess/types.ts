import { CloudFormationTemplateConfig } from "../shared/project/project-context.js";

export interface CodeScanResult {
    semgrepSummaryPath: string;
    banditSummaryPath: string | null;
    syftSummaryPath: string;
}

export interface TemplateResult extends CloudFormationTemplateConfig {
    checkovSummaryPath: string | null;
    securityMatrixPath: string | null;
    diagramPath: string | null;
    threatModelPath: string | null;
}

export interface TerraformTemplateResult {
    tfProjectName: string;
    tfProjectRootPath: string;
    tfOutputFolderPath: string;
    checkovSummaryPath: string | null;
    terraformMatrixPath: string | null;
    diagramPath: string | null;
    threatModelPath: string | null;
}

export interface LicenseHeaderCheckResult {
    hasExistingHeaders: boolean;
    fileCount: number;
}

// export interface ProjectPathResult {
//     path: string;
//     exists: boolean;
//     defaultPath: string;
// }