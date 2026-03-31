import * as fs from 'fs/promises';
import { SrtLogger } from '../../../shared/logging/srt-logger.js';
import { ScanResult } from '../types.js';

export class ScannerUtils {
    public static filterResults(results: ScanResult[], ignoredDirectoryNames: string[]): ScanResult[] {
        return results.filter((result: ScanResult) => {
            if (!result.path) return true;

            const filePath = result.path.toLowerCase();
            return !ignoredDirectoryNames.some(dir => filePath.includes(dir.toLowerCase()));
        });
    }

    public static mapSeverity(severity: string): string {
        switch (severity.toLowerCase()) {
            case 'high':
                return 'High';
            case 'medium':
                return 'Medium';
            case 'low':
                return 'Low';
            default:
                return 'Unknown';
        }
    }

    public static async readJsonFile<T>(filePath: string): Promise<T | null> {
        try {
            const content = await fs.readFile(filePath, { encoding: 'utf-8' });
            return JSON.parse(content) as T;
        } catch (error) {
            SrtLogger.logError(`Error reading JSON file ${filePath}`, error as Error);
            return null;
        }
    }

    public static async writeJsonFile<T>(filePath: string, data: T): Promise<void> {
        try {
            await fs.writeFile(filePath, JSON.stringify(data, null, 2));
        } catch (error) {
            SrtLogger.logError(`Error writing JSON file ${filePath}`, error as Error);
        }
    }

    public static async ensureDirectoryExists(dirPath: string): Promise<void> {
        try {
            await fs.mkdir(dirPath, { recursive: true });
        } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== 'EEXIST') {
                SrtLogger.logError(`Error creating directory ${dirPath}`, error as Error);
                throw error;
            }
        }
    }
}
