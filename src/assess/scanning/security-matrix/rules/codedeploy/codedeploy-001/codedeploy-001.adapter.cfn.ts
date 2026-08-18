import { AdapterFactory, CfnContext } from '../../../controls/types.js';
import { Codedeploy001Adapter } from './codedeploy-001.adapter.js';

export class Codedeploy001CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::CodeDeploy::DeploymentGroup'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): Codedeploy001CfnAdapter {
    return new Codedeploy001CfnAdapter(context);
  }
}

const INTRINSIC_PREFIX = 'Fn::';

class Codedeploy001CfnAdapter implements Codedeploy001Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  hasConfiguredAlarms(): boolean | undefined {
    const properties = this.ctx.resource.Properties as Record<string, unknown> | undefined;
    const alarmConfiguration = properties?.['AlarmConfiguration'];
    if (alarmConfiguration === undefined) return false;
    if (!this.isRecord(alarmConfiguration)) return undefined;
    if (this.isUnresolvedIntrinsic(alarmConfiguration)) return undefined;

    const monitoringActive = this.isMonitoringActive(alarmConfiguration['Enabled']);
    if (monitoringActive === false) return false;

    const namesAnAlarm = this.namesAnAlarm(alarmConfiguration['Alarms']);
    // With monitoring switched on, the alarm list decides the outcome. With an
    // unreadable on/off flag, an alarm list that provably names nothing still
    // monitors nothing, so only a list that does name an alarm stays unknown.
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
    if (typeof enabled === 'string') {
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
    if (!Array.isArray(alarms)) return undefined;
    return alarms.some(alarm => this.identifiesAnAlarm(alarm));
  }

  /**
   * An alarm entry only monitors deployments when it actually names an alarm.
   * An entry whose name is blank or missing altogether identifies nothing.
   */
  private identifiesAnAlarm(alarm: unknown): boolean {
    if (typeof alarm === 'string') return alarm.trim().length > 0;
    if (!this.isRecord(alarm)) return true;
    const name = alarm['Name'];
    if (name === undefined) return false;
    if (typeof name === 'string') return name.trim().length > 0;
    return true;
  }

  private isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
  }

  private isUnresolvedIntrinsic(value: Record<string, unknown>): boolean {
    return Object.keys(value).some(key => key.startsWith(INTRINSIC_PREFIX) || key === 'Ref');
  }
}
