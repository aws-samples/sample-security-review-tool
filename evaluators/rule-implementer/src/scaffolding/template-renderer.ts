import * as fs from 'node:fs';
import * as path from 'node:path';
import * as url from 'node:url';
import { Substitutions } from './substitutions.js';

const TEMPLATE_DIR = path.join(path.dirname(url.fileURLToPath(import.meta.url)), 'templates');

export class TemplateRenderer {
    constructor(private readonly templateName: string) { }

    public writeTo(outputPath: string, substitutions: Substitutions): void {
        fs.writeFileSync(outputPath, this.render(substitutions));
    }

    private render(substitutions: Substitutions): string {
        const raw = fs.readFileSync(path.join(TEMPLATE_DIR, this.templateName), 'utf8');
        return substitutions.apply(raw);
    }
}
