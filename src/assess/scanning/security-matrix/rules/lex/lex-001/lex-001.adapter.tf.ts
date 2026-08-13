import { AdapterFactory, TfContext } from '../../../controls/types.js';
import { ChildDirectedSetting, Lex001Adapter } from './lex-001.adapter.js';

export class Lex001TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = ['aws_lexv2models_bot', 'aws_lex_bot'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): Lex001TfAdapter {
    return new Lex001TfAdapter(context);
  }
}

class Lex001TfAdapter implements Lex001Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  childDirected(): ChildDirectedSetting {
    return this.resourceType === 'aws_lex_bot'
      ? this.interpret(this.values()['child_directed'])
      : this.childDirectedFromDataPrivacy();
  }

  private childDirectedFromDataPrivacy(): ChildDirectedSetting {
    const dataPrivacy = this.values()['data_privacy'];
    if (dataPrivacy === undefined || dataPrivacy === null) return 'absent';
    if (Array.isArray(dataPrivacy)) return this.combine(dataPrivacy.map(block => this.fromBlock(block)));
    return this.fromBlock(dataPrivacy);
  }

  private fromBlock(block: unknown): ChildDirectedSetting {
    if (!this.isRecord(block)) return 'unknown';
    return this.interpret(block['child_directed']);
  }

  /**
   * Multiple blocks only demonstrate child-directed protection when every one of them
   * resolves to true. Any known non-true block decides the outcome.
   */
  private combine(outcomes: ChildDirectedSetting[]): ChildDirectedSetting {
    if (outcomes.length === 0) return 'absent';
    const nonTrue = outcomes.find(outcome => outcome !== true && outcome !== 'unknown');
    if (nonTrue !== undefined) return nonTrue;
    return outcomes.includes('unknown') ? 'unknown' : true;
  }

  private interpret(value: unknown): ChildDirectedSetting {
    if (value === undefined) return 'absent';
    if (value === null) return 'unknown';
    if (typeof value === 'boolean') return value;
    if (typeof value === 'string') return this.interpretText(value);
    if (typeof value === 'number') return 'other';
    return 'unknown';
  }

  private interpretText(value: string): ChildDirectedSetting {
    const normalized = value.trim().toLowerCase();
    if (normalized === 'true') return true;
    if (normalized === 'false') return false;
    return 'other';
  }

  private values(): Record<string, unknown> {
    const values = this.ctx.resource.values as unknown;
    return this.isRecord(values) ? values : {};
  }

  private isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
  }
}
