import { ScanResult } from '../../assess/scanning/types.js';

export interface DashboardOptions {
    srtFolderPath: string;
    projectName: string;
    scanDate: Date;
    showAll?: boolean;
}

export interface DiagramData {
    stackName: string;
    content: string;
}

export interface ThreatModelData {
    stackName: string;
    content: string;
}

export interface DashboardData {
    meta: DashboardMeta;
    summary: DashboardSummary;
    issues: ScanResult[];
    threatModels: ThreatModelData[];
    diagrams: DiagramData[];
    bom: BomPackage[] | null;
    projectSummary: string | null;
    showAll: boolean;
}

export interface DashboardMeta {
    projectName: string;
    scanDate: string;
    generatedAt: string;
    toolVersion: string;
}

export interface DashboardSummary {
    total: number;
    blocking: number;
    open: number;
    reopened: number;
    resolved: number;
    suppressed: number;
    byPriority: PriorityCounts;
    bySource: Record<string, number>;
}

export interface PriorityCounts {
    high: number;
    medium: number;
    low: number;
}

export interface BomPackage {
    type: string;
    name: string;
    version: string;
    license: string;
    path: string;
}
