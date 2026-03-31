import { CodeScanResult, TemplateResult } from '../types.js';

export interface ReportingOptions {
    codeScanResult: CodeScanResult;
    templateResults: TemplateResult[];
    generateXlsx: boolean;
    projectSummary: string | null;
}