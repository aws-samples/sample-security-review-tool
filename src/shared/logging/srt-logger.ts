import * as fs from 'fs';
import * as path from 'path';
import { Logger, createLogger, format } from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import { AppPaths } from '../app-config/app-paths.js';

export type LogValue = string | number | boolean | undefined | null | object;
export interface LogContext {
    [key: string]: LogValue;
}

export class SrtLogger {
    private static instance: SrtLogger;
    private logger: Logger;
    private logsFolderPath: string;
    private logFileName: string;

    private constructor(logsFolderPath: string, logFileName: string) {
        this.logsFolderPath = logsFolderPath;
        this.logFileName = logFileName;

        this.ensureLogsDirectoryExists();

        this.logger = createLogger({
            level: 'debug',
            format: format.combine(
                format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
                format.printf(({ timestamp, level, message, ...metadata }) => {
                    const meta = Object.keys(metadata).length > 0 ? ` ${SrtLogger.formatContext(metadata as Record<string, LogValue>)}` : '';
                    return `${timestamp} [${level.toUpperCase()}]: ${message}${meta}`;
                })
            ),
            transports: [
                new DailyRotateFile({
                    filename: path.join(this.logsFolderPath, this.logFileName),
                    datePattern: 'YY-MM-DD',
                    maxSize: '10mb',
                    maxFiles: '7d'
                })
            ]
        });
    }

    private static formatContext(context: LogContext): string {
        const pairs = Object.entries(context)
            .filter(([_, v]) => v !== undefined)
            .map(([k, v]) => {
                if (typeof v === 'object' && v !== null) {
                    return `${k}=${JSON.stringify(v)}`;
                }
                return `${k}=${v}`;
            });
        return pairs.length > 0 ? `{${pairs.join(', ')}}` : '';
    }

    public static initialize(logsFolderPath?: string): void {
        const resolvedLogsFolderPath = logsFolderPath ?? path.join(AppPaths.getAppDir(), "logs");
        const logFileName = "srt-tool.log"

        if (!SrtLogger.instance) SrtLogger.instance = new SrtLogger(resolvedLogsFolderPath, logFileName);
    }

    private static getInstance(): SrtLogger {
        if (!SrtLogger.instance) {
            throw new Error('SrtLogger not initialized. Call SrtLogger.initialize() first.');
        }
        return SrtLogger.instance;
    }

    public static logError(message: string, error: unknown, context?: LogContext): void {
        const instance = SrtLogger.getInstance();
        const errorDetails = error instanceof Error
            ? { errorName: error.name, error: error.message, stack: error.stack }
            : { error: String(error) };
        instance.logger.error(message, { ...context, ...errorDetails });
    }

    private ensureLogsDirectoryExists(): void {
        try {
            if (!fs.existsSync(this.logsFolderPath)) {
                fs.mkdirSync(this.logsFolderPath, { recursive: true });
            }
        } catch (error) {
            console.error('Failed to create logs directory:', error);
            throw error;
        }
    }
}
