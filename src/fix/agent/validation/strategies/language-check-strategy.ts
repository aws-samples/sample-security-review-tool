import * as fs from 'fs/promises';
import * as path from 'path';
import { FixChange } from '../../../types.js';
import { ProjectContext } from '../../../../shared/project/project-context.js';
import { CommandRunner } from '../../../../shared/command-execution/command-runner.js';
import { StrategyResult, ValidationStrategy } from '../types.js';

type LanguageCheck = (filePath: string, context: ProjectContext) => Promise<StrategyResult>;

/**
 * Runs a minimal language-level check on each staged code file so common
 * mistakes (unbalanced braces, bad syntax, invalid JSON) are caught before
 * the diff is shown to the user.
 */
export class LanguageCheckStrategy implements ValidationStrategy {
    public readonly name = 'language-check';

    private readonly commandRunner = new CommandRunner();

    public async validate(changes: FixChange[], context: ProjectContext): Promise<StrategyResult[]> {
        const results: StrategyResult[] = [];
        for (const change of changes) {
            const check = this.pickCheck(change.filePath);
            if (!check) continue;
            results.push(await check(change.filePath, context));
        }
        return results;
    }

    private pickCheck(filePath: string): LanguageCheck | null {
        const ext = path.extname(filePath).toLowerCase();
        switch (ext) {
            case '.ts':
            case '.tsx':
                return this.checkTypescript.bind(this);
            case '.js':
            case '.mjs':
            case '.cjs':
                return this.checkJavascript.bind(this);
            case '.py':
                return this.checkPython.bind(this);
            case '.json':
                return this.checkJson.bind(this);
            default:
                return null;
        }
    }

    private async checkJson(filePath: string): Promise<StrategyResult> {
        const strategy = this.strategyName('json', filePath);
        try {
            const content = await fs.readFile(filePath, 'utf-8');
            JSON.parse(content);
            return { strategy, isValid: true };
        } catch (error) {
            return { strategy, isValid: false, output: (error as Error).message };
        }
    }

    private async checkJavascript(filePath: string): Promise<StrategyResult> {
        const strategy = this.strategyName('node-check', filePath);
        return this.run(strategy, `node --check "${filePath}"`, path.dirname(filePath));
    }

    private async checkTypescript(filePath: string, context: ProjectContext): Promise<StrategyResult> {
        const tsconfig = await this.findNearestTsconfig(filePath, context.getProjectRootFolderPath());
        if (tsconfig) {
            const strategy = this.strategyName('tsc-project', filePath);
            return this.run(strategy, `npx --no-install tsc --noEmit -p "${tsconfig}"`, path.dirname(tsconfig));
        }
        const strategy = this.strategyName('tsc-file', filePath);
        const command = `npx --no-install tsc --noEmit --allowJs --skipLibCheck --target es2020 --module esnext --moduleResolution node "${filePath}"`;
        return this.run(strategy, command, path.dirname(filePath));
    }

    private async checkPython(filePath: string, context: ProjectContext): Promise<StrategyResult> {
        const strategy = this.strategyName('py_compile', filePath);
        const pythonPath = await this.resolvePython(context);
        return this.run(strategy, `${pythonPath} -m py_compile "${filePath}"`, path.dirname(filePath));
    }

    private async resolvePython(context: ProjectContext): Promise<string> {
        if (await context.hasPythonVenv()) {
            const venv = await context.getPythonVenvConfig();
            return `"${venv.pythonPath}"`;
        }
        return 'python3';
    }

    private async run(strategy: string, command: string, cwd: string): Promise<StrategyResult> {
        try {
            await this.commandRunner.exec(command, cwd, true);
            return { strategy, isValid: true };
        } catch (error) {
            return { strategy, isValid: false, output: this.extractCommandOutput(error) };
        }
    }

    private extractCommandOutput(error: unknown): string {
        const anyError = error as { stderr?: string; stdout?: string; message?: string };
        const stderr = (anyError.stderr ?? '').toString().trim();
        const stdout = (anyError.stdout ?? '').toString().trim();
        const message = anyError.message ?? 'Command failed';
        return [stderr, stdout, message].filter(part => part.length > 0).join('\n');
    }

    private async findNearestTsconfig(filePath: string, rootFolderPath: string): Promise<string | null> {
        let dir = path.dirname(path.resolve(filePath));
        const root = path.resolve(rootFolderPath);
        while (dir.startsWith(root)) {
            const candidate = path.join(dir, 'tsconfig.json');
            if (await this.exists(candidate)) return candidate;
            const parent = path.dirname(dir);
            if (parent === dir) break;
            dir = parent;
        }
        return null;
    }

    private async exists(filePath: string): Promise<boolean> {
        try {
            await fs.access(filePath);
            return true;
        } catch {
            return false;
        }
    }

    private strategyName(kind: string, filePath: string): string {
        return `${this.name}:${kind}:${path.basename(filePath)}`;
    }
}
