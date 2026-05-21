import { AdapterFactory, CfnContext } from '../../../controls/types.js';
import { Lambda004Adapter } from './lambda-004.adapter.js';

const ACTIVE_TRACING_MODE = 'Active';

export class Lambda004CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::Lambda::Function', 'AWS::Serverless::Function'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): Lambda004CfnAdapter {
    return new Lambda004CfnAdapter(context);
  }
}

class Lambda004CfnAdapter implements Lambda004Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  hasTracingConfigured(): boolean {
    const properties = this.ctx.resource.Properties as Record<string, unknown> | undefined;
    if (!properties) return false;

    if (this.resourceType === 'AWS::Serverless::Function') {
      return this.isTracingModeActiveOrUnresolved(properties.Tracing);
    }

    return this.isCfnTracingConfigActive(properties.TracingConfig);
  }

  private isCfnTracingConfigActive(tracingConfig: unknown): boolean {
    if (!tracingConfig || typeof tracingConfig !== 'object') return false;
    const mode = (tracingConfig as Record<string, unknown>).Mode;
    return this.isTracingModeActiveOrUnresolved(mode);
  }

  private isTracingModeActiveOrUnresolved(mode: unknown): boolean {
    if (mode === ACTIVE_TRACING_MODE) return true;
    return this.isUnresolvedIntrinsic(mode);
  }

  /**
   * A CloudFormation scalar property value is considered unresolved when it is
   * an object representing an intrinsic function (e.g. { Ref: ... },
   * { 'Fn::If': [...] }) rather than a literal string. When the tracing mode
   * cannot be determined at analysis time, the rule must not flag the
   * resource to avoid false positives.
   */
  private isUnresolvedIntrinsic(value: unknown): boolean {
    return typeof value === 'object' && value !== null;
  }
}
