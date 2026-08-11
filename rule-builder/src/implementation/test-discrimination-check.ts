import * as fs from 'node:fs';

const NULL_ASSERTION = /expect\([^)]*\)\s*\.\s*toBeNull\(\)/;
const NOT_NULL_ASSERTION = /expect\([^)]*\)\s*\.\s*(not\s*\.\s*toBeNull\(\)|toBeTruthy\(\))/;
const FINDING_ASSERTION = /expect\([^)]*\)\s*\.\s*to(Be|Equal)\(\s*['"][A-Z][A-Z0-9]*-\d+['"]\s*\)/;
const SKIPPED_SUITE = /(describe|it)\s*\.\s*skip\s*\(/;

export interface DiscriminationResult { discriminates: boolean; reason?: string; }

/**
 * A test file asserting only one outcome passes against a control that always
 * returns that outcome, so it cannot fail for the right reason. Flagging that
 * here keeps a requirement from being reported as covered when the generated
 * tests would accept a permissive implementation.
 */
export function checkDiscrimination(testFilePath: string): DiscriminationResult {
    if (!fs.existsSync(testFilePath)) return { discriminates: false, reason: 'file was not created' };

    const source = fs.readFileSync(testFilePath, 'utf8');
    if (SKIPPED_SUITE.test(source)) return { discriminates: true };

    const assertsPass = NULL_ASSERTION.test(source);
    const assertsFlag = NOT_NULL_ASSERTION.test(source) || FINDING_ASSERTION.test(source);

    if (assertsPass && assertsFlag) return { discriminates: true };
    if (!assertsPass && !assertsFlag) {
        return { discriminates: false, reason: 'no pass or flag assertion found' };
    }
    return {
        discriminates: false,
        reason: assertsPass
            ? 'every test expects no finding, so a control that never flags would pass'
            : 'every test expects a finding, so a control that always flags would pass',
    };
}
