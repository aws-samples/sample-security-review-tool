import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export async function typecheckGeneratedTest(testPath: string): Promise<string[]> {
    console.log(`    Typechecking generated test at ${testPath}...`);
    try {
        await execFileAsync('npx', ['tsc', '--noEmit', '--module', 'nodenext', '--moduleResolution', 'nodenext', '--target', 'ES2023', '--strict', '--esModuleInterop', '--skipLibCheck', testPath], { encoding: 'utf8', timeout: 30_000 });
        console.log(`    Typecheck passed for ${testPath}`);
        return [];
    } catch (error: any) {
        const output = (error.stdout ?? '') + (error.stderr ?? '');
        console.log(`    Typecheck failed for ${testPath}`);
        return output.split('\n').filter((line: string) => line.includes(testPath));
    }
}
