// TODO: Copy from src/core/scanners/base-scanner.ts
export interface ScanResult {
    source: string;
    path?: string;
    line?: number;
    issue?: string;
    fix?: string;
    check_id?: string;
    priority?: string;
    references?: string;
    status?: string;
    suppressionReason?: string;
    stack?: string;
    resourceType?: string;
    resourceName?: string;
    cdkPath?: string;
    isCustomResource?: boolean;
}

export interface Scanner {
    scan(projectRootFolderPath: string, outputFilePath: string): Promise<void>;
    summarize(scanFilePath: string, summaryFilePath: string, projectRootFolderPath?: string): Promise<void>;
}
