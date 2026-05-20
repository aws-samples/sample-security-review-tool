import { AdapterFactory, TfContext, IacRemediation } from '../../../controls/types.js';
import { Lambda004Adapter } from './lambda-004.adapter.js';

const ACTIVE_TRACING_MODE = 'Active';
const UNKNOWN_PLAN_VALUE_KEY = '__unknown__';

export class Lambda004TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = ['aws_lambda_function'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): Lambda004TfAdapter {
    return new Lambda004TfAdapter(context);
  }
}

class Lambda004TfAdapter implements Lambda004Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  hasTracingConfigured(): boolean {
    const values = this.ctx.resource.values as Record<string, unknown> | undefined;
    if (!values) return false;
    return this.hasActiveTracingMode(values.tracing_config);
  }

  private hasActiveTracingMode(tracingConfig: unknown): boolean {
    if (tracingConfig === undefined || tracingConfig === null) return false;

    // In terraform-json plan output, nested blocks are surfaced as arrays.
    // A non-array object normally indicates a malformed/non-block shape; only
    // when it is explicitly marked as unresolved at plan time should the rule
    // skip flagging to avoid a false positive.
    if (!Array.isArray(tracingConfig)) {
      return this.isUnresolvedPlanValue(tracingConfig);
    }

    return tracingConfig.some(block => this.isActiveOrUnresolvedBlock(block));
  }

  private isActiveOrUnresolvedBlock(block: unknown): boolean {
    if (!block || typeof block !== 'object') return false;
    const mode = (block as Record<string, unknown>).mode;
    if (mode === ACTIVE_TRACING_MODE) return true;
    return this.isUnresolvedPlanValue(mode);
  }

  /**
   * A Terraform plan value is treated as unresolved when it is an object
   * placeholder rather than a literal scalar. terraform-json surfaces values
   * unknown at plan time via `after_unknown`; consumers may forward those as
   * sentinel objects. When the tracing mode cannot be determined, the rule
   * must not flag the resource to avoid false positives.
   */
  private isUnresolvedPlanValue(value: unknown): boolean {
    if (typeof value !== 'object' || value === null) return false;
    return UNKNOWN_PLAN_VALUE_KEY in (value as Record<string, unknown>);
  }

  getRemediation(_scenario: string): IacRemediation | null {
    return null;
  }
}
