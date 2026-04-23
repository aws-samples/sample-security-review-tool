import * as fs from 'node:fs';
import * as path from 'node:path';
import { execSync } from 'node:child_process';
import { BedrockRuntimeClient } from '@aws-sdk/client-bedrock-runtime';
import type { FixtureFormat, RuleEntry } from '../../../shared/rule-catalog/src/index.js';
import { RuleCatalog } from '../../../shared/rule-catalog/src/index.js';
import type {
    FixtureFile,
    FixtureMeta,
    GeneratedFixture,
    RelatedRuleContext,
    ValidationFailure,
} from './types.js';
import { SynthAgent } from './synth-agent.js';
import { FixtureValidator } from './fixture-validator.js';

const MAX_ATTEMPTS = 3;
const META_FILENAME = 'fixture-meta.json';
const NPM_INSTALL_TIMEOUT_MS = 5 * 60 * 1000;

/**
 * Generates, caches, and validates one fixture per (rule, format). Re-runs
 * with a cached fixture are a no-op as long as the rule source hash is
 * unchanged. Failed validations are fed back into the synth agent up to
 * MAX_ATTEMPTS times; after that the rule is marked ungeneratable.
 */
export class GeneratorCoordinator {
    private readonly synthAgent: SynthAgent;
    private readonly validator: FixtureValidator;

    constructor(
        private readonly bedrockClient: BedrockRuntimeClient,
        private readonly fixturesRoot: string,
        private readonly ruleCatalog: RuleCatalog,
    ) {
        this.synthAgent = new SynthAgent(bedrockClient);
        this.validator = new FixtureValidator();
    }

    public async generate(
        rule: RuleEntry,
        format: FixtureFormat,
        options: { regenerate?: boolean } = {},
    ): Promise<GeneratedFixture> {
        const fixtureDir = this.fixtureDirFor(rule, format);
        const cached = this.readCachedMeta(fixtureDir);
        if (!options.regenerate && cached && this.isCacheValid(cached, rule)) {
            await this.restoreDepsIfMissing(fixtureDir);
            return { meta: cached, fixtureDir, ungeneratable: false };
        }

        this.clearFixtureDir(fixtureDir);
        fs.mkdirSync(fixtureDir, { recursive: true });

        let previousFailure: ValidationFailure | null = null;
        const relatedRules = new Map<string, RelatedRuleContext>();
        for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            const files = await this.synthAgent.generate(rule, format, previousFailure, [...relatedRules.values()]);
            this.writeFixtureFiles(fixtureDir, files);

            const installFailure = await this.ensureDepsInstalled(fixtureDir);
            if (installFailure) {
                previousFailure = installFailure;
                this.clearFixtureDirKeepRoot(fixtureDir);
                continue;
            }

            const validation = await this.validator.validate(fixtureDir, rule);
            if (validation.ok) {
                const meta = this.buildMeta(rule, format, attempt, relatedRules);
                this.writeMeta(fixtureDir, meta);
                this.gitInit(fixtureDir);
                return { meta, fixtureDir, ungeneratable: false };
            }
            previousFailure = validation.failure ?? { kind: 'parse', message: 'unknown validation failure' };
            this.mergeRelatedRules(relatedRules, previousFailure);
            this.clearFixtureDirKeepRoot(fixtureDir);
        }

        return {
            meta: this.buildMeta(rule, format, MAX_ATTEMPTS, relatedRules),
            fixtureDir,
            ungeneratable: true,
            ungeneratableReason: previousFailure
                ? `${previousFailure.kind}: ${previousFailure.message}`
                : 'unknown',
        };
    }

    private mergeRelatedRules(
        collected: Map<string, RelatedRuleContext>,
        failure: ValidationFailure,
    ): void {
        if (failure.kind !== 'scan-extra-rules') return;
        const checkIds = failure.extraCheckIds ?? [];
        for (const checkId of checkIds) {
            if (collected.has(checkId)) continue;
            const entry = this.ruleCatalog.find(checkId);
            if (!entry) continue;
            collected.set(checkId, {
                checkId: entry.checkId,
                description: entry.description,
                ruleBody: entry.ruleBody,
            });
        }
    }

    private async restoreDepsIfMissing(fixtureDir: string): Promise<void> {
        const packageJsonPath = path.join(fixtureDir, 'package.json');
        if (!fs.existsSync(packageJsonPath)) return;
        const nodeModulesPath = path.join(fixtureDir, 'node_modules');
        if (fs.existsSync(nodeModulesPath)) return;

        const failure = await this.ensureDepsInstalled(fixtureDir);
        if (failure) {
            const details = failure.details ? `\n${failure.details}` : '';
            throw new Error(`Restoring dependencies for cached fixture failed: ${failure.message}${details}`);
        }
    }

    private async ensureDepsInstalled(fixtureDir: string): Promise<ValidationFailure | null> {
        const packageJsonPath = path.join(fixtureDir, 'package.json');
        if (!fs.existsSync(packageJsonPath)) return null;

        try {
            execSync('npm install --silent --no-audit --no-fund --prefer-offline', {
                cwd: fixtureDir,
                stdio: 'pipe',
                timeout: NPM_INSTALL_TIMEOUT_MS,
            });
            return null;
        } catch (error) {
            const { stdout, stderr, message } = this.extractExecError(error);
            const details = [stderr, stdout, message].filter(s => s.length > 0).join('\n').slice(0, 2000);
            return {
                kind: 'deps-install-failed',
                message: 'npm install failed for the generated package.json',
                details,
            };
        }
    }

    private extractExecError(error: unknown): { stdout: string; stderr: string; message: string } {
        const anyError = error as { stdout?: unknown; stderr?: unknown; message?: unknown };
        return {
            stdout: (anyError.stdout ?? '').toString().trim(),
            stderr: (anyError.stderr ?? '').toString().trim(),
            message: (anyError.message ?? '').toString().trim(),
        };
    }

    private isCacheValid(cached: FixtureMeta, rule: RuleEntry): boolean {
        if (cached.sourceHash !== rule.sourceHash) return false;
        for (const [checkId, cachedHash] of Object.entries(cached.relatedRuleHashes ?? {})) {
            const currentEntry = this.ruleCatalog.find(checkId);
            if (!currentEntry || currentEntry.sourceHash !== cachedHash) return false;
        }
        return true;
    }

    public fixtureDirFor(rule: RuleEntry, format: FixtureFormat): string {
        const safeCheckId = rule.checkId.replace(/[^A-Za-z0-9_.-]/g, '_');
        return path.join(this.fixturesRoot, rule.scanner, format, safeCheckId);
    }

    private readCachedMeta(fixtureDir: string): FixtureMeta | null {
        const metaPath = path.join(fixtureDir, META_FILENAME);
        if (!fs.existsSync(metaPath)) return null;
        try {
            return JSON.parse(fs.readFileSync(metaPath, 'utf8')) as FixtureMeta;
        } catch {
            return null;
        }
    }

    private writeFixtureFiles(fixtureDir: string, files: FixtureFile[]): void {
        for (const file of files) {
            const safeRelative = this.sanitizeRelative(file.relativePath);
            const absolute = path.join(fixtureDir, safeRelative);
            fs.mkdirSync(path.dirname(absolute), { recursive: true });
            fs.writeFileSync(absolute, file.content, 'utf8');
        }
    }

    private sanitizeRelative(relativePath: string): string {
        const normalized = path.normalize(relativePath).replace(/^(\.\.[/\\])+/, '');
        if (path.isAbsolute(normalized)) {
            return path.basename(normalized);
        }
        return normalized;
    }

    private clearFixtureDir(fixtureDir: string): void {
        if (fs.existsSync(fixtureDir)) fs.rmSync(fixtureDir, { recursive: true, force: true });
    }

    private clearFixtureDirKeepRoot(fixtureDir: string): void {
        if (!fs.existsSync(fixtureDir)) return;
        for (const entry of fs.readdirSync(fixtureDir)) {
            fs.rmSync(path.join(fixtureDir, entry), { recursive: true, force: true });
        }
    }

    private buildMeta(
        rule: RuleEntry,
        format: FixtureFormat,
        attempts: number,
        relatedRules: Map<string, RelatedRuleContext>,
    ): FixtureMeta {
        const meta: FixtureMeta = {
            checkId: rule.checkId,
            scanner: rule.scanner,
            format,
            sourceHash: rule.sourceHash,
            generatedAt: new Date().toISOString(),
            validationAttempts: attempts,
        };
        if (relatedRules.size > 0) {
            meta.relatedRuleHashes = this.collectRelatedRuleHashes(relatedRules);
        }
        return meta;
    }

    private collectRelatedRuleHashes(relatedRules: Map<string, RelatedRuleContext>): Record<string, string> {
        const hashes: Record<string, string> = {};
        for (const checkId of relatedRules.keys()) {
            const entry = this.ruleCatalog.find(checkId);
            if (entry) hashes[checkId] = entry.sourceHash;
        }
        return hashes;
    }

    private writeMeta(fixtureDir: string, meta: FixtureMeta): void {
        fs.writeFileSync(path.join(fixtureDir, META_FILENAME), JSON.stringify(meta, null, 2), 'utf8');
    }

    private gitInit(fixtureDir: string): void {
        execSync('git init -q', { cwd: fixtureDir, stdio: 'ignore' });
        execSync('git add -A', { cwd: fixtureDir, stdio: 'ignore' });
        execSync('git -c user.email=evaluator@srt -c user.name=Evaluator commit -q -m "fixture baseline"', {
            cwd: fixtureDir,
            stdio: 'ignore',
        });
    }
}
