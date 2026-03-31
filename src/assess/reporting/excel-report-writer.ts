import * as path from 'path';
import ExcelJS from 'exceljs';
import { getFriendlyDate } from '../../shared/utils/date-utils.js';
import { readJsonFile } from '../../shared/file-system/file-utils.js';
import { Threat } from '../template-processing/threat-model-report-generator.js';
import { CodeScanResult, TemplateResult } from '../types.js';

export interface ExcelReportOptions {
    srtOutputFolderPath: string;
    codeScanResult: CodeScanResult;
    templateResults: TemplateResult[];
}

interface SyftSummaryItem {
    type: string;
    count: number;
}

interface SyftPackage {
    name: string;
    version: string;
    license: string;
    path: string;
}

interface SyftPackageGroup {
    type: string;
    packages: SyftPackage[];
}

interface SyftData {
    summary: {
        totalPackages: number;
        packagesByType: SyftSummaryItem[];
    };
    packages: SyftPackageGroup[];
}

interface SyftRow {
    Type: string;
    Name: string;
    Version: string | number;
    License: string;
    Path: string;
}

export class ExcelReportWriter {
    private workbook!: ExcelJS.Workbook;

    public async write(options: ExcelReportOptions): Promise<string> {
        this.initializeWorkbook();
        await this.addSemgrepSheet(options.codeScanResult.semgrepSummaryPath);
        await this.addBanditSheet(options.codeScanResult.banditSummaryPath);
        await this.addBomSheet(options.codeScanResult.syftSummaryPath);
        await this.addTemplateSheets(options.templateResults);
        return await this.writeToFile(options.srtOutputFolderPath);
    }

    private initializeWorkbook(): void {
        this.workbook = new ExcelJS.Workbook();
    }

    private async addSemgrepSheet(summaryPath: string): Promise<void> {
        const data = await readJsonFile<Record<string, unknown>[]>(summaryPath);
        if (data) {
            this.addSheetFromJson(data, 'Semgrep');
        }
    }

    private async addBanditSheet(summaryPath: string | null): Promise<void> {
        if (!summaryPath) return;

        const data = await readJsonFile<Record<string, unknown>[]>(summaryPath);
        if (data) {
            this.addSheetFromJson(data, 'Bandit');
        }
    }

    private async addBomSheet(summaryPath: string): Promise<void> {
        const data = await readJsonFile<unknown[]>(summaryPath);
        if (!data) return;

        const rows = this.extractBomRows(data);
        this.addSheetFromJson(rows, 'BOM');
    }

    private extractBomRows(data: unknown[]): unknown[] {
        if (this.isSyftFormat(data)) {
            return this.flattenSyftPackages(data[0] as SyftData);
        }
        return data;
    }

    private isSyftFormat(data: unknown[]): boolean {
        if (data.length !== 1) return false;

        const item = data[0] as Record<string, unknown>;
        return item.summary !== undefined && item.packages !== undefined;
    }

    private flattenSyftPackages(syftData: SyftData): SyftRow[] {
        const rows: SyftRow[] = [];

        rows.push(this.createSummaryRow('Total Packages', syftData.summary.totalPackages));

        for (const item of syftData.summary.packagesByType) {
            rows.push(this.createSummaryRow(`${item.type} packages`, item.count));
        }

        rows.push(this.createSeparatorRow());

        for (const group of syftData.packages) {
            for (const pkg of group.packages) {
                rows.push(this.createPackageRow(group.type, pkg));
            }
        }

        return rows;
    }

    private createSummaryRow(name: string, count: number): SyftRow {
        return { Type: 'SUMMARY', Name: name, Version: count, License: '', Path: '' };
    }

    private createSeparatorRow(): SyftRow {
        return { Type: '--------', Name: '--------', Version: '--------', License: '--------', Path: '--------' };
    }

    private createPackageRow(type: string, pkg: SyftPackage): SyftRow {
        return { Type: type, Name: pkg.name, Version: pkg.version, License: pkg.license, Path: pkg.path };
    }

    private async addTemplateSheets(templateResults: TemplateResult[]): Promise<void> {
        if (templateResults.length === 0) return;

        const checkovData = await this.collectTemplateData<Record<string, unknown>>(templateResults, 'checkovSummaryPath');
        const securityMatrixData = await this.collectTemplateData<Record<string, unknown>>(templateResults, 'securityMatrixPath');
        const threatModelData = await this.collectTemplateData<Threat>(templateResults, 'threatModelPath');

        if (checkovData.length > 0) {
            this.addSheetFromJson(checkovData, 'Checkov');
        }

        if (securityMatrixData.length > 0) {
            this.addSheetFromJson(securityMatrixData, 'Security Matrix');
        }

        if (threatModelData.length > 0) {
            this.addSheetFromJson(threatModelData, 'Threat Model');
        }
    }

    private async collectTemplateData<T>(templateResults: TemplateResult[], pathProperty: keyof TemplateResult): Promise<T[]> {
        const combined: T[] = [];

        for (const result of templateResults) {
            const filePath = result[pathProperty] as string | null;
            if (filePath) {
                const data = await readJsonFile<T[]>(filePath);
                if (data) {
                    combined.push(...data);
                }
            }
        }

        return combined;
    }

    private addSheetFromJson(data: unknown[], sheetName: string): void {
        if (data.length === 0) return;

        const worksheet = this.workbook.addWorksheet(sheetName);
        const firstRow = data[0] as Record<string, unknown>;
        const headers = Object.keys(firstRow);

        worksheet.columns = headers.map(header => ({ header, key: header }));

        for (const row of data) {
            const record = row as Record<string, unknown>;
            worksheet.addRow(record);
        }
    }

    private async writeToFile(outputFolderPath: string): Promise<string> {
        const filePath = path.join(outputFolderPath, `srt ${getFriendlyDate()}.xlsx`);
        await this.workbook.xlsx.writeFile(filePath);
        return filePath;
    }
}
