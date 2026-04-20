import * as path from 'path';
import { ProjectContext } from '../../../shared/project/project-context.js';
import { CdkConstructResolver } from '../../cdk/cdk-construct-resolver.js';
import { AgentTool, ToolOutput } from '../types.js';

/**
 * Locates the CDK source construct corresponding to a finding's cdkPath
 * (populated from the CloudFormation resource's `aws:cdk:path` metadata).
 *
 * This short-circuits the search loop the FixAgent otherwise performs
 * (list_files → grep → read_file across multiple casings) whenever a
 * finding originates from synthesized CloudFormation in a CDK project.
 */
export class FindCdkConstructTool implements AgentTool {
    private readonly resolver: CdkConstructResolver;

    constructor(
        private readonly context: ProjectContext,
        private readonly templateFilePath: string | undefined,
    ) {
        this.resolver = new CdkConstructResolver(context);
    }

    public readonly definition = {
        toolSpec: {
            name: 'find_cdk_construct',
            description:
                'Locate the CDK source construct for a finding with a cdkPath (aws:cdk:path). Returns the source file path, line number, the enclosing stack class, and the construct source block. Call this FIRST for any finding with a cdkPath before list_files / grep / read_file.',
            inputSchema: {
                json: {
                    type: 'object',
                    properties: {
                        cdkPath: {
                            type: 'string',
                            description: 'The aws:cdk:path value from the finding (e.g. "MyStack/api-bucket/Resource").',
                        },
                    },
                    required: ['cdkPath'],
                },
            },
        },
    };

    public async invoke(input: Record<string, unknown>): Promise<ToolOutput> {
        const cdkPath = String(input.cdkPath ?? '').trim();
        if (!cdkPath) {
            return { text: 'Error: "cdkPath" is required.', isError: true };
        }

        const construct = await this.resolver.findConstructForIssue(cdkPath, this.templateFilePath);
        if (!construct) {
            return {
                text: `No CDK construct found for cdkPath="${cdkPath}". Fall back to list_files / grep to locate the source.`,
                isError: true,
            };
        }

        const relativeFilePath = this.toProjectRelative(construct.filePath);
        return {
            json: {
                cdkPath,
                filePath: relativeFilePath,
                lineNumber: construct.lineNumber,
                stackClassName: construct.className,
                constructCode: construct.constructCode,
            },
        };
    }

    private toProjectRelative(absolutePath: string): string {
        const projectRoot = this.context.getProjectRootFolderPath();
        const relative = path.relative(projectRoot, absolutePath);
        return relative && !relative.startsWith('..') ? relative : absolutePath;
    }
}
