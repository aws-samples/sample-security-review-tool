import { Tool } from '@aws-sdk/client-bedrock-runtime';
import { ProjectContext } from '../../shared/project/project-context.js';
import { AgentTool, ToolOutput } from './types.js';
import { WorkspaceGuard } from './workspace-guard.js';
import { EditRecorder } from './edit-recorder.js';
import { AgentLogger } from './agent-logger.js';
import { ReadFileTool } from './tools/read-file-tool.js';
import { ListFilesTool } from './tools/list-files-tool.js';
import { GrepTool } from './tools/grep-tool.js';
import { EditFileTool } from './tools/edit-file-tool.js';
import { WriteFileTool } from './tools/write-file-tool.js';
import { ValidateFixTool } from './tools/validate-fix-tool.js';
import { FinishTool } from './tools/finish-tool.js';
import { FixValidator } from './validation/fix-validator.js';
import { ValidationState } from './validation/validation-state.js';

export class ToolRegistry {
    private readonly tools = new Map<string, AgentTool>();
    public readonly validationState = new ValidationState();
    public readonly editRecorder = new EditRecorder(this.validationState);
    public readonly finishTool: FinishTool;

    constructor(context: ProjectContext, private readonly agentLogger: AgentLogger) {
        const guard = new WorkspaceGuard(context.getProjectRootFolderPath());
        const validator = new FixValidator(context, this.editRecorder);
        this.finishTool = new FinishTool(this.editRecorder, this.validationState);

        this.register(new ReadFileTool(guard, this.editRecorder));
        this.register(new ListFilesTool(context, guard));
        this.register(new GrepTool(context, guard));
        this.register(new EditFileTool(guard, this.editRecorder));
        this.register(new WriteFileTool(guard, this.editRecorder));
        this.register(new ValidateFixTool(this.editRecorder, validator, this.validationState));
        this.register(this.finishTool);
    }

    public describe(): Tool[] {
        return Array.from(this.tools.values()).map(tool => tool.definition as Tool);
    }

    public async invoke(name: string, input: Record<string, unknown>): Promise<ToolOutput> {
        this.agentLogger.toolInvoked(name, input);
        const start = Date.now();

        const tool = this.tools.get(name);
        const output = tool
            ? await tool.invoke(input)
            : { text: `Unknown tool: ${name}`, isError: true };

        this.agentLogger.toolCompleted(name, output, Date.now() - start);
        return output;
    }

    private register(tool: AgentTool): void {
        const name = tool.definition.toolSpec?.name;
        if (!name) throw new Error('Tool is missing a name in its definition.');
        this.tools.set(name, tool);
    }
}
