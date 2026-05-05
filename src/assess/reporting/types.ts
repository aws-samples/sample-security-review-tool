import { CodeScanResult, TemplateResult, TerraformTemplateResult } from '../types.js';

export interface ReportingOptions {
    codeScanResult: CodeScanResult;
    templateResults: TemplateResult[];
    generateXlsx: boolean;
    projectSummary: string | null;
    terraformResults?: TerraformTemplateResult[];
}

export interface AssessmentSummary {
    totalIssues: number;
    newIssues: number;
    resolvedIssues: number;
    reopenedIssues: number;
    highPriority: number;
    mediumPriority: number;
    lowPriority: number;
    bySource: Record<string, number>;
}