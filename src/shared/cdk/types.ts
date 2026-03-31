export interface CdkConstructInfo {
    className: string;
    filePath: string;
    context: string;
    constructCode: string;
    lineNumber: number;
}

export interface CdkProjectConfig {
    name: string;
    rootPath: string;
    outputPath: string;
    entrypointPath: string | null;
}

export interface CdkSynthesisResult {
    project: CdkProjectConfig;
    success: boolean;
    error?: string;
}
