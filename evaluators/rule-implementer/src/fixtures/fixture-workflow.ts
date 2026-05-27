import * as fs from 'node:fs';
import * as path from 'node:path';
import { RuleContext } from '../shared/rule-context.js';
import { FixtureGenerationAgent } from './fixture-generation-agent.js';

export class FixtureWorkflow {
    constructor(private readonly context: RuleContext) { }

    public async run(): Promise<void> {
        this.prepareFixtures();
        await this.prepareCdkFixtureResources();        
    }

    private prepareFixtures(): void {
        console.log(`CDK Fixture Output Folder Path: ${this.context.cdkFixtureOutputFolderPath}`);
        console.log(`CDK Fixture Template Folder Path: ${this.context.cdkFixtureTemplateFolderPath}`);

        fs.rmSync(this.context.cdkFixtureOutputFolderPath, { recursive: true, force: true });
        fs.cpSync(this.context.cdkFixtureTemplateFolderPath, this.context.cdkFixtureOutputFolderPath, { recursive: true });
    }

    private async prepareCdkFixtureResources(): Promise<void> {
        if (fs.existsSync(this.context.cdkFixtureResourceFilePath)) {
            fs.cpSync(this.context.cdkFixtureResourceFilePath, path.join(this.context.cdkFixtureOutputFolderPath, 'fixture-stack.ts'));
        } else {
            const generator = new FixtureGenerationAgent(this.context);
            await generator.invoke();

            const generatedResourcePath = path.join(this.context.cdkFixtureOutputFolderPath, 'fixture-stack.ts');
            fs.cpSync(generatedResourcePath, this.context.cdkFixtureResourceFilePath);
        }
    }
}
