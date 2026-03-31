import chalk from 'chalk';
import { SrtLogger } from '../logging/srt-logger.js';

interface ErrorInfo {
	source: string;
	type: string;
	message: string;
	context?: Record<string, any>;
	consoleMessage?: string;
	shouldThrow?: boolean;
}

export async function handleError(info: ErrorInfo): Promise<void> {
	if (info.shouldThrow) {
		const message = info.consoleMessage || 'An error occurred';
		SrtLogger.logError(`Fatal error: ${info.type}`, new Error(info.message), { source: info.source, context: info.context });
		console.error(chalk.red(`\n${message}\nReason: ${info.message}`));
		throw new Error(`[${info.source}] ${info.type}: ${info.message}`);
	} else if (info.consoleMessage) {
		console.log(chalk.yellow(`\n${info.consoleMessage}`));
	}
}
