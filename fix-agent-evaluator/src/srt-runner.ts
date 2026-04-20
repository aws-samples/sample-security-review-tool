import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { AssessCoordinator } from '../../src/assess/coordinator.js';
import { FixCoordinator } from '../../src/fix/coordinator.js';
import { SrtLogger } from '../../src/shared/logging/srt-logger.js';
import { BedrockConfig } from '../../src/config/aws/bedrock-config.js';
import type { ScanResult } from '../../src/assess/scanning/types.js';
import type { Fix } from '../../src/fix/types.js';
import type { FixRunRecord } from './types.js';
import { AgentSessionParser } from './log-collector.js';
import { GitSnapshot } from './git-snapshot.js';

const LOG_FILE_NAME = 'srt-tool.log';

/**
 * Drives the SRT scan + fix pipeline programmatically. Avoids the interactive
 * CLI so prompt wording changes can't break us, and gives us a 1:1 mapping
 * between finding and agent session.
 */
export class SrtRunner {
    private readonly logsFolderPath: string;

    constructor(private readonly projectPath: string) {
        this.logsFolderPath = path.join(os.homedir(), '.srt', 'logs');
    }

    public async initialize(): Promise<void> {
        fs.mkdirSync(this.logsFolderPath, { recursive: true });
        SrtLogger.initialize(this.logsFolderPath);
        this.initializeBedrockConfig();
    }

    /**
     * Initializes BedrockConfig without going through SRT's AppConfig, which
     * looks for srtconfig.json next to the running binary's dirname
     * (`process.execPath`). When we run under `bun`, that dirname points at
     * the bun interpreter, not the srt install, so AppConfig would never find
     * the config.
     *
     * We instead prefer (in order):
     *   1. AWS_REGION / AWS_PROFILE environment variables,
     *   2. an srtconfig.json discovered at a path provided by SRT_CONFIG_PATH,
     *   3. an srtconfig.json found in common srt install locations.
     */
    private initializeBedrockConfig(): void {
        const envRegion = process.env.AWS_REGION ?? process.env.AWS_DEFAULT_REGION;
        const envProfile = process.env.AWS_PROFILE ?? 'default';
        if (envRegion) {
            BedrockConfig.initialize(envProfile, envRegion);
            return;
        }

        const configPath = this.findSrtConfigPath();
        if (configPath) {
            const config = JSON.parse(fs.readFileSync(configPath, 'utf8')) as { AWS_PROFILE?: string; AWS_REGION?: string };
            if (config.AWS_REGION) {
                BedrockConfig.initialize(config.AWS_PROFILE ?? 'default', config.AWS_REGION);
                return;
            }
        }

        throw new Error(
            'Could not determine AWS profile/region for Bedrock. Set AWS_REGION (and optionally AWS_PROFILE) ' +
            'in your environment, or point SRT_CONFIG_PATH at an existing srtconfig.json produced by `srt config`.',
        );
    }

    private findSrtConfigPath(): string | null {
        const candidates = [
            process.env.SRT_CONFIG_PATH,
            path.join(os.homedir(), '.local', 'bin', 'srtconfig.json'),
            path.join(os.homedir(), 'bin', 'srtconfig.json'),
            path.join('/usr/local/bin', 'srtconfig.json'),
        ].filter((candidate): candidate is string => typeof candidate === 'string');

        for (const candidate of candidates) {
            if (fs.existsSync(candidate)) return candidate;
        }
        return null;
    }

    public async scan(): Promise<void> {
        const coordinator = new AssessCoordinator(this.projectPath, () => {});
        await coordinator.assess('Apache-2.0', false, false, false, false);
    }

    public async fixAllHighFindings(): Promise<FixRunRecord[]> {
        const coordinator = await FixCoordinator.create(this.projectPath, () => {});
        const issues = await coordinator.getIssues('high', 'open');

        const git = new GitSnapshot(this.projectPath);
        await git.ensureGitRepository();

        const records: FixRunRecord[] = [];
        for (const issue of issues) {
            const record = await this.runSingleFinding(coordinator, git, issue);
            records.push(record);
        }
        return records;
    }

    private async runSingleFinding(
        coordinator: FixCoordinator,
        git: GitSnapshot,
        issue: ScanResult
    ): Promise<FixRunRecord> {
        const logOffset = this.currentLogSize();
        const startedAt = Date.now();

        const fix = await this.safeGenerateFix(coordinator, issue);
        const applied = await this.safeApplyFix(coordinator, issue, fix);

        const durationMs = Date.now() - startedAt;
        const newLogLines = this.readLogLinesSince(logOffset);
        const session = new AgentSessionParser().parseSession(newLogLines, issue);
        const diff = applied ? await git.diffUnstaged() : '';
        await git.stageAll();

        return { issue, fix, applied, session, diff, durationMs };
    }

    private async safeGenerateFix(coordinator: FixCoordinator, issue: ScanResult): Promise<Fix | null> {
        try {
            return await coordinator.generateFix(issue);
        } catch (error) {
            SrtLogger.logError('Evaluator: generateFix threw', error as Error, {
                checkId: issue.check_id,
                path: issue.path,
            });
            console.error(`  ! generateFix failed for ${issue.check_id} ${issue.path}: ${(error as Error).message}`);
            return null;
        }
    }

    private async safeApplyFix(coordinator: FixCoordinator, issue: ScanResult, fix: Fix | null): Promise<boolean> {
        if (!fix) return false;
        try {
            await coordinator.applyFix(issue, fix);
            return true;
        } catch (error) {
            SrtLogger.logError('Evaluator: applyFix threw', error as Error, {
                checkId: issue.check_id,
                path: issue.path,
            });
            return false;
        }
    }

    private currentLogSize(): number {
        const logFilePath = this.todaysLogFilePath();
        if (!fs.existsSync(logFilePath)) return 0;
        return fs.statSync(logFilePath).size;
    }

    private readLogLinesSince(byteOffset: number): string[] {
        const logFilePath = this.todaysLogFilePath();
        if (!fs.existsSync(logFilePath)) return [];
        const fd = fs.openSync(logFilePath, 'r');
        try {
            const size = fs.statSync(logFilePath).size;
            if (size <= byteOffset) return [];
            const buffer = Buffer.alloc(size - byteOffset);
            fs.readSync(fd, buffer, 0, buffer.length, byteOffset);
            return buffer.toString('utf8').split('\n').filter(line => line.length > 0);
        } finally {
            fs.closeSync(fd);
        }
    }

    private todaysLogFilePath(): string {
        // winston-daily-rotate-file writes to <filename>.YY-MM-DD by default.
        // Find the newest matching rotation file so we always pick today's log.
        const base = LOG_FILE_NAME;
        const files = fs.existsSync(this.logsFolderPath) ? fs.readdirSync(this.logsFolderPath) : [];
        const matches = files.filter(name => name.startsWith(`${base}.`)).sort();
        if (matches.length === 0) return path.join(this.logsFolderPath, base);
        return path.join(this.logsFolderPath, matches[matches.length - 1]);
    }
}
