import * as fs from 'node:fs';
import * as path from 'node:path';
import { RuleContext } from '../../shared/fixture-paths.js';
import { toClassName, toInstanceName, toServiceControlsName } from './naming.js';

export class RegistrationWriter {
    private readonly controlImportPath: string;
    private readonly cfnAdapterClassName: string;
    private readonly tfAdapterClassName: string;
    private readonly controlInstanceName: string;
    private readonly serviceControlsName: string;

    constructor(private readonly context: RuleContext) {
        this.controlInstanceName = toInstanceName(context.ruleId) + 'Control';
        this.cfnAdapterClassName = toClassName(context.ruleId) + 'CfnAdapterFactory';
        this.tfAdapterClassName = toClassName(context.ruleId) + 'TfAdapterFactory';
        this.controlImportPath = `../${context.safeRuleId}/${context.safeRuleId}`;
        this.serviceControlsName = toServiceControlsName(context.service);
    }

    public register(): void {
        this.ensureServiceControlsIndex();
        this.ensureGlobalRegistryEntry();
    }

    private ensureServiceControlsIndex(): void {
        const filePath = this.context.serviceControlsIndexPath;
        fs.mkdirSync(path.dirname(filePath), { recursive: true });

        if (this.serviceIndexAlreadyContainsRule(filePath)) return;

        const content = fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf8') : '';
        const isNewFormat = content.includes('RegisteredControl[]');

        if (isNewFormat) {
            this.appendToServiceIndex(filePath, content);
        } else {
            this.createServiceIndex(filePath);
        }
    }

    private serviceIndexAlreadyContainsRule(filePath: string): boolean {
        if (!fs.existsSync(filePath)) return false;
        const content = fs.readFileSync(filePath, 'utf8');
        return content.includes(`from '${this.controlImportPath}.control.js'`);
    }

    private createServiceIndex(filePath: string): void {
        const lines = [
            `import { RegisteredControl } from '../../../controls/types.js';`,
            `import { ${this.controlInstanceName} } from '${this.controlImportPath}.control.js';`,
            `import { ${this.cfnAdapterClassName} } from '${this.controlImportPath}.adapter.cfn.js';`,
            `import { ${this.tfAdapterClassName} } from '${this.controlImportPath}.adapter.tf.js';`,
            ``,
            `export const ${this.serviceControlsName}: RegisteredControl[] = [`,
            `  { control: ${this.controlInstanceName}, cfnAdapter: new ${this.cfnAdapterClassName}(), tfAdapter: new ${this.tfAdapterClassName}() },`,
            `];`,
            ``,
        ];
        fs.writeFileSync(filePath, lines.join('\n'));
    }

    private appendToServiceIndex(filePath: string, content: string): void {
        const importLines = [
            `import { ${this.controlInstanceName} } from '${this.controlImportPath}.control.js';`,
            `import { ${this.cfnAdapterClassName} } from '${this.controlImportPath}.adapter.cfn.js';`,
            `import { ${this.tfAdapterClassName} } from '${this.controlImportPath}.adapter.tf.js';`,
        ].join('\n');

        const arrayEntry = `  { control: ${this.controlInstanceName}, cfnAdapter: new ${this.cfnAdapterClassName}(), tfAdapter: new ${this.tfAdapterClassName}() },`;

        const updatedContent = content
            .replace(/(import .+\n)(\n)/, `$1${importLines}\n$2`)
            .replace(/];(\n?)$/, `${arrayEntry}\n];$1`);

        fs.writeFileSync(filePath, updatedContent);
    }

    private ensureGlobalRegistryEntry(): void {
        const filePath = this.context.controlsRegistryPath;
        const content = fs.readFileSync(filePath, 'utf8');

        if (content.includes(`from './${this.context.service}/controls/index.js'`)) return;

        const importLine = `import { ${this.serviceControlsName} } from './${this.context.service}/controls/index.js';`;
        const spreadEntry = `  ...${this.serviceControlsName},`;

        const updatedContent = content
            .replace(/(import .+\n)(\n)/, `$1${importLine}\n$2`)
            .replace(/(RegisteredControl\[] = \[\n)/, `$1${spreadEntry}\n`);

        fs.writeFileSync(filePath, updatedContent);
    }
}
