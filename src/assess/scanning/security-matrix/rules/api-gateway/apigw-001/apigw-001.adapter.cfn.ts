import { AdapterFactory, CfnContext, Resource } from '../../../controls/types.js';
import { Apigw001Adapter } from './apigw-001.adapter.js';

const ACCESS_LOG_PROPERTY_BY_TYPE: Record<string, string> = {
  'AWS::ApiGateway::Stage': 'AccessLogSetting',
  'AWS::ApiGatewayV2::Stage': 'AccessLogSettings',
};

const LOG_GROUP_TYPE = 'AWS::Logs::LogGroup';

type RetentionStatus = 'valid' | 'invalid' | 'unknown';

export class Apigw001CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = Object.keys(ACCESS_LOG_PROPERTY_BY_TYPE);

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): Apigw001CfnAdapter {
    return new Apigw001CfnAdapter(context);
  }
}

class Apigw001CfnAdapter implements Apigw001Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  hasAccessLogging(): boolean {
    const settings = this.getAccessLogSettings();
    if (!this.isNonEmptyObject(settings)) return false;
    return this.hasValidDestination(settings as Record<string, unknown>);
  }

  hasProperLogRetention(): boolean {
    const settings = this.getAccessLogSettings() as Record<string, unknown> | undefined;
    if (!settings) return true;
    const destinationArn = settings['DestinationArn'];
    if (typeof destinationArn !== 'string') return true;
    const logGroup = this.findInTemplateLogGroup(destinationArn);
    if (!logGroup) return true;
    return this.hasRetention(logGroup);
  }

  private getAccessLogSettings(): unknown {
    const propertyName = ACCESS_LOG_PROPERTY_BY_TYPE[this.resourceType];
    if (!propertyName) return undefined;
    const properties = (this.ctx.resource.Properties ?? {}) as Record<string, unknown>;
    return properties[propertyName];
  }

  private hasValidDestination(settings: Record<string, unknown>): boolean {
    const destinationArn = settings['DestinationArn'];
    if (destinationArn === undefined || destinationArn === null) return false;
    if (typeof destinationArn === 'string' && destinationArn.length === 0) return false;
    return true;
  }

  private findInTemplateLogGroup(destinationArn: string): Resource | undefined {
    const resources = (this.ctx.template.Resources ?? {}) as Record<string, Resource>;
    for (const [logicalId, resource] of Object.entries(resources)) {
      if (resource.Type !== LOG_GROUP_TYPE) continue;
      if (this.referencesLogGroup(destinationArn, logicalId, resource)) return resource;
    }
    return undefined;
  }

  private referencesLogGroup(destinationArn: string, logicalId: string, logGroup: Resource): boolean {
    if (destinationArn === logicalId) return true;
    const properties = (logGroup.Properties ?? {}) as Record<string, unknown>;
    const logGroupName = properties['LogGroupName'];
    if (typeof logGroupName === 'string' && destinationArn.includes(logGroupName)) return true;
    return false;
  }

  private hasRetention(logGroup: Resource): boolean {
    const properties = (logGroup.Properties ?? {}) as Record<string, unknown>;
    if (!('RetentionInDays' in properties)) return false;
    const retention = properties['RetentionInDays'];
    if (retention === undefined || retention === null) return false;
    const status = this.classifyRetention(retention);
    return status !== 'invalid';
  }

  private classifyRetention(value: unknown): RetentionStatus {
    if (typeof value === 'number') return value > 0 ? 'valid' : 'invalid';
    if (typeof value === 'string') return 'invalid';
    if (typeof value === 'boolean') return 'invalid';
    if (value && typeof value === 'object') return this.classifyIntrinsic(value as Record<string, unknown>);
    return 'invalid';
  }

  private classifyIntrinsic(intrinsic: Record<string, unknown>): RetentionStatus {
    if ('Fn::If' in intrinsic) {
      const args = intrinsic['Fn::If'];
      if (!Array.isArray(args) || args.length !== 3) return 'unknown';
      const branches = [args[1], args[2]].map(branch => this.classifyRetention(branch));
      if (branches.includes('invalid')) return 'invalid';
      if (branches.includes('unknown')) return 'unknown';
      return 'valid';
    }
    // Other intrinsic functions (Fn::ImportValue, Ref, Fn::FindInMap that survived, etc.)
    // are unresolvable at scan time — treat as unknown.
    return 'unknown';
  }

  private isNonEmptyObject(value: unknown): boolean {
    if (!value || typeof value !== 'object') return false;
    return Object.keys(value as Record<string, unknown>).length > 0;
  }
}
