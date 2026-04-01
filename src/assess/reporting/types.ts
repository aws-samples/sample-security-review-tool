import { CodeScanResult, TemplateResult } from '../types.js';

export interface ReportingOptions {
    codeScanResult: CodeScanResult;
    templateResults: TemplateResult[];
    generateXlsx: boolean;
    projectSummary: string | null;
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