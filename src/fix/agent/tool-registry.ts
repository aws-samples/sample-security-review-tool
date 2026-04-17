import { Tool } from '@aws-sdk/client-bedrock-runtime';
import { ProjectContext } from '../../shared/project/project-context.js';
import { AgentTool, ToolOutput } from './types.js';
import { WorkspaceGuard } from './workspace-guard.js';
import { EditRecorder } from './edit-recorder.js';
import { ReadFileTool } from './tools/read-file-tool.js';
import { ListFilesTool } from './tools/list-files-tool.js';
import { GrepTool } from './tools/grep-tool.js';
import { ApplyPatchTool } from './tools/apply-patch-tool.js';
import { FinishTool } from './tools/finish-tool.js';

export class ToolRegistry {
    private readonly tools = new Map<string, AgentTool>();
    public readonly editRecorder = new EditRecorder();
    public readonly finishTool = new FinishTool();

    constructor(context: ProjectContext) {
        const guard = new WorkspaceGuard(context.getProjectRootFolderPath());
        this.register(new ReadFileTool(guard, this.editRecorder));
        this.register(new ListFilesTool(context, guard));
        this.register(new GrepTool(context, guard));
        this.register(new ApplyPatchTool(guard, this.editRecorder));
        this.register(this.finishTool);
    }

    public describe(): Tool[] {
        return Array.from(this.tools.values()).map(tool => tool.definition as Tool);
    }

    public async invoke(name: string, input: Record<string, unknown>): Promise<ToolOutput> {
        const tool = this.tools.get(name);
        if (!tool) {
            return { text: `Unknown tool: ${name}`, isError: true };
        }
        return tool.invoke(input);
    }

    private register(tool: AgentTool): void {
        const name = tool.definition.toolSpec?.name;
        if (!name) throw new Error('Tool is missing a name in its definition.');
        this.tools.set(name, tool);
    }
}
