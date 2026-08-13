import { AdapterFactory, CfnContext } from '../../../controls/types.js';
import { ChildDirectedSetting, Lex001Adapter } from './lex-001.adapter.js';

const CONDITIONAL_KEY = 'Fn::If';
const CONDITIONAL_BRANCH_COUNT = 3;

export class Lex001CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::Lex::Bot'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): Lex001CfnAdapter {
    return new Lex001CfnAdapter(context);
  }
}

class Lex001CfnAdapter implements Lex001Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  childDirected(): ChildDirectedSetting {
    const dataPrivacy = this.properties()['DataPrivacy'];
    if (dataPrivacy === undefined || dataPrivacy === null) return 'absent';
    if (Array.isArray(dataPrivacy)) return this.combine(dataPrivacy.map(entry => this.fromDeclaration(entry)));
    return this.fromDeclaration(dataPrivacy);
  }

  private fromDeclaration(declaration: unknown): ChildDirectedSetting {
    if (declaration === undefined || declaration === null) return 'absent';
    if (!this.isRecord(declaration)) return 'unknown';
    return this.interpret(declaration['ChildDirected']);
  }

  /**
   * Multiple declarations only demonstrate child-directed protection when every one of
   * them resolves to true. Any known non-true declaration decides the outcome.
   */
  private combine(outcomes: ChildDirectedSetting[]): ChildDirectedSetting {
    if (outcomes.length === 0) return 'absent';
    const nonTrue = outcomes.find(outcome => outcome !== true && outcome !== 'unknown');
    if (nonTrue !== undefined) return nonTrue;
    return outcomes.includes('unknown') ? 'unknown' : true;
  }

  private interpret(value: unknown): ChildDirectedSetting {
    if (value === undefined || value === null) return 'absent';
    if (typeof value === 'boolean') return value;
    if (typeof value === 'string') return this.interpretText(value);
    if (typeof value === 'number') return 'other';
    if (this.isRecord(value)) return this.interpretSelection(value);
    return 'unknown';
  }

  /**
   * An unresolvable selection is only compliant-capable when at least one reachable
   * branch could yield true. When every branch is a known non-true value the bot is
   * non-compliant regardless of how the condition resolves.
   */
  private interpretSelection(value: Record<string, unknown>): ChildDirectedSetting {
    const branches = this.conditionalBranches(value);
    if (!branches) return 'unknown';
    const outcomes = branches.map(branch => this.interpret(branch));
    if (outcomes.some(outcome => outcome === true || outcome === 'unknown')) return 'unknown';
    return false;
  }

  private conditionalBranches(value: Record<string, unknown>): unknown[] | null {
    const conditional = value[CONDITIONAL_KEY];
    if (!Array.isArray(conditional) || conditional.length !== CONDITIONAL_BRANCH_COUNT) return null;
    return conditional.slice(1);
  }

  private interpretText(value: string): ChildDirectedSetting {
    const normalized = value.trim().toLowerCase();
    if (normalized === 'true') return true;
    if (normalized === 'false') return false;
    return 'other';
  }

  private properties(): Record<string, unknown> {
    const properties = (this.ctx.resource as { Properties?: unknown }).Properties;
    return this.isRecord(properties) ? properties : {};
  }

  private isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
  }
}
