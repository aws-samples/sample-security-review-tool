import * as fs from 'node:fs';
import * as path from 'node:path';
import { RuleContext } from '../shared/rule-context.js';

interface ConversionCheckpoint {
    ruleId: string;
    service: string;
    sourceDescription: string;
    rewrittenDescription: string;
}

export class ConversionCheckpointStore {
    private readonly filePath: string;

    constructor(
        private readonly ruleId: string,
        private readonly service: string,
        stateRootFolderPath = path.join(RuleContext.srtRootFolderPath(), 'rule-builder', '.state', 'conversions'),
    ) {
        this.filePath = path.join(stateRootFolderPath, this.safeName(service), `${this.safeName(ruleId)}.json`);
    }

    public read(sourceDescription: string): string | null {
        if (!fs.existsSync(this.filePath)) return null;

        const checkpoint = this.parse();
        if (checkpoint.sourceDescription !== sourceDescription) return null;
        return checkpoint.rewrittenDescription;
    }

    public write(sourceDescription: string, rewrittenDescription: string): void {
        const checkpoint: ConversionCheckpoint = {
            ruleId: this.ruleId,
            service: this.service,
            sourceDescription,
            rewrittenDescription,
        };

        fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
        fs.writeFileSync(this.filePath, JSON.stringify(checkpoint, null, 2));
    }

    public remove(): void {
        fs.rmSync(this.filePath, { force: true });
    }

    private parse(): ConversionCheckpoint {
        const parsed: unknown = JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
        if (!this.isCheckpoint(parsed)) {
            throw new Error(`Conversion checkpoint for ${this.ruleId} is invalid: ${this.filePath}`);
        }
        return parsed;
    }

    private isCheckpoint(value: unknown): value is ConversionCheckpoint {
        if (typeof value !== 'object' || value === null) return false;
        const checkpoint = value as Partial<ConversionCheckpoint>;
        return checkpoint.ruleId === this.ruleId
            && checkpoint.service === this.service
            && typeof checkpoint.sourceDescription === 'string'
            && typeof checkpoint.rewrittenDescription === 'string';
    }

    private safeName(value: string): string {
        return value.replace(/[^A-Za-z0-9_.-]/g, '_').toLowerCase();
    }
}
