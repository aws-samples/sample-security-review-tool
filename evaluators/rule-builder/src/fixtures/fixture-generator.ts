import * as fs from 'node:fs';
import * as path from 'node:path';
import { RuleContext } from '../shared/rule-context.js';
import { FixtureGenerationAgent } from './fixture-generation-agent.js';
import { FixtureType } from './fixture-type.js';

export class FixtureGenerator {
    constructor(private readonly context: RuleContext, private readonly fixtureType: FixtureType) { }

    public async generate(): Promise<void> {
        this.prepareTemplate();
        await this.prepareResources();
    }

    private prepareTemplate(): void {
        fs.rmSync(this.fixtureType.outputFolderPath, { recursive: true, force: true });
        fs.cpSync(this.fixtureType.templateFolderPath, this.fixtureType.outputFolderPath, { recursive: true });
    }

    private async prepareResources(): Promise<void> {
        const outputResourcePath = path.join(this.fixtureType.outputFolderPath, this.fixtureType.resourceFileName);

        if (fs.existsSync(this.fixtureType.resourceFilePath)) {
            fs.cpSync(this.fixtureType.resourceFilePath, outputResourcePath);
        } else {
            await new FixtureGenerationAgent(this.context, this.fixtureType).invoke();
            fs.cpSync(outputResourcePath, this.fixtureType.resourceFilePath);
        }
    }
}
