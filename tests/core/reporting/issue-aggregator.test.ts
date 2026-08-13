import { beforeEach, describe, expect, it, vi } from 'vitest';
import { readJsonFile, fileExists } from '../../../src/shared/file-system/file-utils.js';
import { IssueAggregator } from '../../../src/assess/reporting/issue-aggregator.js';
import type { ScanResult } from '../../../src/assess/scanning/types.js';

vi.mock('../../../src/shared/file-system/file-utils.js');

const ISSUES_PATH = 'issues.json';
const MATRIX_PATH = 'security-matrix.json';

const knownIssue: ScanResult = {
    source: 'security-matrix',
    path: 'terraform',
    resourceType: 'aws_api_gateway_stage',
    resourceName: 'aws_api_gateway_stage.legacy',
    check_id: 'APIGW-003',
    issue: 'The API stage is protected only by a legacy web ACL association',
    fix: 'Guidance from when the issue was first detected.',
    priority: 'HIGH',
    status: 'open',
    firstDetectedAt: '2026-08-12T14:59:17.825Z',
    assessmentCount: 4,
};

function aggregate(rescanned: ScanResult[]) {
    vi.mocked(fileExists).mockResolvedValue(true);
    vi.mocked(readJsonFile).mockImplementation(async (filePath: string) => {
        if (filePath === ISSUES_PATH) return [{ ...knownIssue }];
        if (filePath === MATRIX_PATH) return rescanned;
        return null;
    });

    const context = { getIssuesFilePath: () => ISSUES_PATH } as unknown as ConstructorParameters<typeof IssueAggregator>[0];

    return new IssueAggregator(context).aggregateResults({
        codeScanResult: { semgrepSummaryPath: 'semgrep.json', banditSummaryPath: null } as never,
        templateResults: [{ checkovSummaryPath: null, securityMatrixPath: MATRIX_PATH } as never],
        generateXlsx: false,
        projectSummary: null,
    });
}

beforeEach(() => {
    vi.clearAllMocks();
});

describe('IssueAggregator', () => {
    it('replaces stored guidance with the guidance from the latest scan', async () => {
        const { issues } = await aggregate([{ ...knownIssue, fix: 'Improved guidance, including the related-rule constraints.' }]);

        expect(issues).toHaveLength(1);
        expect(issues[0].fix).toBe('Improved guidance, including the related-rule constraints.');
    });

    it('keeps the detection history when refreshing guidance', async () => {
        const { issues } = await aggregate([{ ...knownIssue, fix: 'Improved guidance.' }]);

        expect(issues[0].firstDetectedAt).toBe('2026-08-12T14:59:17.825Z');
        expect(issues[0].assessmentCount).toBe(5);
    });

    it('reopens a fixed issue that the latest scan still reports', async () => {
        vi.mocked(fileExists).mockResolvedValue(true);
        vi.mocked(readJsonFile).mockImplementation(async (filePath: string) => {
            if (filePath === ISSUES_PATH) return [{ ...knownIssue, status: 'fixed', resolvedAt: '2026-08-12T15:05:40.086Z' }];
            if (filePath === MATRIX_PATH) return [{ ...knownIssue }];
            return null;
        });

        const context = { getIssuesFilePath: () => ISSUES_PATH } as unknown as ConstructorParameters<typeof IssueAggregator>[0];
        const { issues, summary } = await new IssueAggregator(context).aggregateResults({
            codeScanResult: { semgrepSummaryPath: 'semgrep.json', banditSummaryPath: null } as never,
            templateResults: [{ checkovSummaryPath: null, securityMatrixPath: MATRIX_PATH } as never],
            generateXlsx: false,
            projectSummary: null,
        });

        expect(issues[0].status).toBe('reopened');
        expect(issues[0].resolvedAt).toBeUndefined();
        expect(summary.reopenedIssues).toBe(1);
    });

    it('marks a stored issue as resolved when the latest scan no longer reports it', async () => {
        const { issues, summary } = await aggregate([]);

        expect(issues[0].status).toBe('resolved');
        expect(issues[0].resolvedAt).toBeDefined();
        expect(summary.resolvedIssues).toBe(1);
    });

    describe('superseded external checks', () => {
        const checkovDuplicate: ScanResult = {
            source: 'Checkov',
            path: 'main.tf',
            line: 19,
            check_id: 'CKV_AWS_59',
            issue: 'Ensure there is no open access to back-end resources through API',
            priority: 'LOW',
            status: 'open',
        };

        function aggregateCheckov(stored: ScanResult[], rescanned: ScanResult[]) {
            vi.mocked(fileExists).mockResolvedValue(true);
            vi.mocked(readJsonFile).mockImplementation(async (filePath: string) => {
                if (filePath === ISSUES_PATH) return stored;
                if (filePath === 'checkov.json') return rescanned;
                return null;
            });

            const context = { getIssuesFilePath: () => ISSUES_PATH } as unknown as ConstructorParameters<typeof IssueAggregator>[0];

            return new IssueAggregator(context).aggregateResults({
                codeScanResult: { semgrepSummaryPath: 'semgrep.json', banditSummaryPath: null } as never,
                templateResults: [{ checkovSummaryPath: 'checkov.json', securityMatrixPath: null } as never],
                generateXlsx: false,
                projectSummary: null,
            });
        }

        it('suppresses a newly reported check that a matrix rule supersedes', async () => {
            const { issues } = await aggregateCheckov([], [{ ...checkovDuplicate }]);

            expect(issues[0].status).toBe('suppressed');
            expect(issues[0].suppressionReason).toBe('Covered by APIGW-004');
        });

        it('suppresses a superseded check that was already stored as open', async () => {
            const { issues } = await aggregateCheckov([{ ...checkovDuplicate }], [{ ...checkovDuplicate }]);

            expect(issues).toHaveLength(1);
            expect(issues[0].status).toBe('suppressed');
        });

        it('leaves checks that no matrix rule supersedes alone', async () => {
            const unrelated = { ...checkovDuplicate, check_id: 'CKV2_AWS_53' };
            const { issues } = await aggregateCheckov([], [unrelated]);

            expect(issues[0].status).toBe('open');
            expect(issues[0].suppressionReason).toBeUndefined();
        });

        it('does not resurrect a superseded check that the latest scan no longer reports', async () => {
            const { issues } = await aggregateCheckov([{ ...checkovDuplicate }], []);

            expect(issues[0].status).toBe('resolved');
        });
    });
});
