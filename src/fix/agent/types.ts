import { FixChange } from '../types.js';
import { ValidationResult } from './validation/types.js';
import { EditSession } from './staging/edit-session.js';
import { LoadedContext } from './prompts/context-loader.js';

export type StrandsStopReason = 'finished' | 'gave_up' | 'max_turns' | 'end_turn' | 'error';

export interface StrandsAgentResult {
    edits: FixChange[];
    comments: string;
    stopReason: StrandsStopReason;
    gaveUpReason?: string;
    validation: ValidationResult | null;
}

export interface AgentSession {
    editSession: EditSession;
    loadedContext: LoadedContext;
    projectRootFolderPath: string;
    comments: string;
    gaveUp: { reason: string } | null;
    finished: boolean;
    lastValidation: ValidationResult | null;
}
