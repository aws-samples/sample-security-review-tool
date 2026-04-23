import * as fs from 'node:fs';
import * as path from 'node:path';
import { execSync } from 'node:child_process';
import { BedrockRuntimeClient } from '@aws-sdk/client-bedrock-runtime';
import type { FixtureFormat, RuleEntry } from '../../../shared/rule-catalog/src/index.js';
import type { FixtureFile, FixtureMeta, GeneratedFixture, ValidationFailure } from './types.js';
import { SynthAgent } from './synth-agent.js';
import { FixtureValidator } from './fixture-validator.js';

const MAX_ATTEMPTS = 3;
const META_FILENAME = 'fixture-meta.json';

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
        if (!options.regenerate && cached && cached.sourceHash === rule.sourceHash) {
            return { meta: cached, fixtureDir, ungeneratable: false };
        }

        this.clearFixtureDir(fixtureDir);
        fs.mkdirSync(fixtureDir, { recursive: true });

        let previousFailure: ValidationFailure | null = null;
        for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            const files = await this.synthAgent.generate(rule, format, previousFailure);
            this.writeFixtureFiles(fixtureDir, files);
            const validation = await this.validator.validate(fixtureDir, rule);
            if (validation.ok) {
                const meta = this.buildMeta(rule, format, attempt);
                this.writeMeta(fixtureDir, meta);
                this.gitInit(fixtureDir);
                return { meta, fixtureDir, ungeneratable: false };
            }
            previousFailure = validation.failure ?? { kind: 'parse', message: 'unknown validation failure' };
            this.clearFixtureDirKeepRoot(fixtureDir);
        }

        return {
            meta: this.buildMeta(rule, format, MAX_ATTEMPTS),
            fixtureDir,
            ungeneratable: true,
            ungeneratableReason: previousFailure
                ? `${previousFailure.kind}: ${previousFailure.message}`
                : 'unknown',
        };
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

    private buildMeta(rule: RuleEntry, format: FixtureFormat, attempts: number): FixtureMeta {
        return {
            checkId: rule.checkId,
            scanner: rule.scanner,
            format,
            sourceHash: rule.sourceHash,
            generatedAt: new Date().toISOString(),
            validationAttempts: attempts,
        };
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
