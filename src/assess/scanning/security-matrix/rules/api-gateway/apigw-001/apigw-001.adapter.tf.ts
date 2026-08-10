import { AdapterFactory, TerraformResource, TfContext } from '../../../controls/types.js';
import { Apigw001Adapter } from './apigw-001.adapter.js';

const LOG_GROUP_TYPE = 'aws_cloudwatch_log_group';

export class Apigw001TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = ['aws_api_gateway_stage', 'aws_apigatewayv2_stage'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): Apigw001TfAdapter {
    return new Apigw001TfAdapter(context);
  }
}

class Apigw001TfAdapter implements Apigw001Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  hasAccessLogging(): boolean {
    const settings = this.getAccessLogSettings();
    if (!settings) return false;
    return this.hasValidDestination(settings);
  }

  hasProperLogRetention(): boolean {
    const settings = this.getAccessLogSettings();
    if (!settings) return true;
    const destinationArn = settings['destination_arn'];
    if (typeof destinationArn !== 'string') return true;
    const logGroup = this.findInPlanLogGroup(destinationArn);
    if (!logGroup) return true;
    return this.hasRetention(logGroup);
  }

  private getAccessLogSettings(): Record<string, unknown> | undefined {
    const values = (this.ctx.resource.values ?? {}) as Record<string, unknown>;
    const accessLogSettings = values['access_log_settings'];
    if (Array.isArray(accessLogSettings)) {
      const firstNonEmpty = accessLogSettings.find(entry => this.isNonEmptyObject(entry));
      return firstNonEmpty as Record<string, unknown> | undefined;
    }
    return this.isNonEmptyObject(accessLogSettings)
      ? (accessLogSettings as Record<string, unknown>)
      : undefined;
  }

  private hasValidDestination(settings: Record<string, unknown>): boolean {
    if (!('destination_arn' in settings)) return false;
    const destinationArn = settings['destination_arn'];
    // null means the value is unknown at plan time — treat as unknown (pass).
    if (destinationArn === null) return true;
    if (destinationArn === undefined) return false;
    if (typeof destinationArn === 'string' && destinationArn.length === 0) return false;
    return true;
  }

  private findInPlanLogGroup(destinationArn: string): TerraformResource | undefined {
    return this.ctx.allResources.find(resource => {
      if (resource.type !== LOG_GROUP_TYPE) return false;
      return this.referencesLogGroup(destinationArn, resource);
    });
  }

  private referencesLogGroup(destinationArn: string, logGroup: TerraformResource): boolean {
    if (destinationArn === logGroup.address) return true;
    const values = (logGroup.values ?? {}) as Record<string, unknown>;
    const logGroupName = values['name'];
    if (typeof logGroupName === 'string' && destinationArn.includes(logGroupName)) return true;
    return false;
  }

  private hasRetention(logGroup: TerraformResource): boolean {
    const values = (logGroup.values ?? {}) as Record<string, unknown>;
    if (!('retention_in_days' in values)) return false;
    const retention = values['retention_in_days'];
    // null means unknown at plan time — treat as unknown (pass).
    if (retention === null) return true;
    if (retention === undefined) return false;
    if (typeof retention === 'number') return retention > 0;
    // Any non-numeric concrete value (string, boolean, object) is not a valid
    // CloudWatch retention period — flag it.
    return false;
  }

  private isNonEmptyObject(value: unknown): boolean {
    if (!value || typeof value !== 'object') return false;
    return Object.keys(value as Record<string, unknown>).length > 0;
  }
}
