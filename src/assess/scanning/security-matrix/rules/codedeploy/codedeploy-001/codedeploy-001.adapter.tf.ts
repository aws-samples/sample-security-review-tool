import { AdapterFactory, TfContext } from '../../../controls/types.js';
import { isUnresolved } from '../../../terraform-rule-base.js';
import { Codedeploy001Adapter } from './codedeploy-001.adapter.js';

export class Codedeploy001TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = ['aws_codedeploy_deployment_group'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): Codedeploy001TfAdapter {
    return new Codedeploy001TfAdapter(context);
  }
}

class Codedeploy001TfAdapter implements Codedeploy001Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  hasConfiguredAlarms(): boolean | undefined {
    const values = (this.ctx.resource.values ?? {}) as Record<string, unknown>;
    const configuration = values['alarm_configuration'];
    if (configuration === undefined) return this.evaluateDynamicConfiguration(values);
    if (isUnresolved(configuration)) return undefined;
    return this.combineOutcomes(this.asArray(configuration).map(block => this.evaluateBlock(block)));
  }

  /**
   * A `dynamic "alarm_configuration"` block is recorded under `dynamic`, never under its
   * own name, and produces a configuration only when its for_each yields an element.
   */
  private evaluateDynamicConfiguration(values: Record<string, unknown>): boolean | undefined {
    const dynamic = values['dynamic'];
    if (typeof dynamic !== 'object' || dynamic === null) return false;

    const entries = this.asArray((dynamic as Record<string, unknown>)['alarm_configuration']);
    if (entries.length === 0) return false;

    return this.combineOutcomes(entries.map(entry => this.evaluateDynamicEntry(entry)));
  }

  private evaluateDynamicEntry(entry: unknown): boolean | undefined {
    if (typeof entry !== 'object' || entry === null) return undefined;

    const { content, for_each: forEach } = entry as Record<string, unknown>;
    if (isUnresolved(forEach)) return undefined;
    if (this.yieldsNothing(forEach)) return false;

    return this.combineOutcomes(this.asArray(content).map(block => this.evaluateBlock(block)));
  }

  private yieldsNothing(forEach: unknown): boolean {
    if (Array.isArray(forEach)) return forEach.length === 0;
    if (typeof forEach === 'object' && forEach !== null) return Object.keys(forEach).length === 0;
    return false;
  }

  private asArray(value: unknown): unknown[] {
    if (value === undefined) return [];
    return Array.isArray(value) ? value : [value];
  }

  private combineOutcomes(outcomes: (boolean | undefined)[]): boolean | undefined {
    if (outcomes.some(outcome => outcome === true)) return true;
    if (outcomes.some(outcome => outcome === undefined)) return undefined;
    return false;
  }

  /**
   * True when the block definitely monitors deployments, false when it definitely
   * does not, and undefined when it cannot be determined.
   */
  private evaluateBlock(block: unknown): boolean | undefined {
    if (typeof block !== 'object' || block === null) return undefined;
    const monitoringActive = this.isMonitoringActive((block as Record<string, unknown>)['enabled']);
    if (monitoringActive === false) return false;

    const namesAnAlarm = this.namesAnAlarm((block as Record<string, unknown>)['alarms']);
    // With an unreadable on/off flag, an alarm list that provably names nothing
    // still monitors nothing; only a list that does name an alarm stays unknown.
    if (monitoringActive === undefined && namesAnAlarm !== false) return undefined;
    return namesAnAlarm;
  }

  /**
   * Alarm monitoring only counts as in effect when it is documented as switched on.
   * An absent flag leaves monitoring undocumented, so it is not active; an
   * unreadable flag is unknown.
   */
  private isMonitoringActive(enabled: unknown): boolean | undefined {
    if (enabled === undefined) return false;
    if (typeof enabled === 'boolean') return enabled;
    if (typeof enabled === 'string' && !isUnresolved(enabled)) {
      const normalized = enabled.trim().toLowerCase();
      if (normalized === 'true') return true;
      if (normalized === 'false') return false;
    }
    return undefined;
  }

  /**
   * True when the alarm list definitely names an alarm, false when it definitely
   * names none, and undefined when the list cannot be read.
   */
  private namesAnAlarm(alarms: unknown): boolean | undefined {
    if (alarms === undefined) return false;
    if (isUnresolved(alarms)) return undefined;
    if (!Array.isArray(alarms)) return undefined;
    return alarms.some(alarm => this.identifiesAnAlarm(alarm));
  }

  /**
   * An alarm entry only monitors deployments when it actually names an alarm.
   * A blank name identifies nothing.
   */
  private identifiesAnAlarm(alarm: unknown): boolean {
    if (typeof alarm !== 'string') return true;
    if (isUnresolved(alarm)) return true;
    return alarm.trim().length > 0;
  }
}
