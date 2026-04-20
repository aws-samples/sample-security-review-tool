import { FixChange } from '../../types.js';
import { ProjectContext } from '../../../shared/project/project-context.js';

export interface StrategyResult {
    strategy: string;
    isValid: boolean;
    output?: string;
}

export interface ValidationResult {
    isValid: boolean;
    checks: StrategyResult[];
    failingCheck?: StrategyResult;
}

export interface ValidationStrategy {
    readonly name: string;
    validate(changes: FixChange[], context: ProjectContext): Promise<StrategyResult[]>;
}
