import { AdapterFactory, TfContext, TerraformResource } from '../../../controls/types.js';
import { Lambda011Adapter } from './lambda-011.adapter.js';

const CLOUDWATCH_ALARM_RESOURCE_TYPE = 'aws_cloudwatch_metric_alarm';
const LAMBDA_METRIC_NAMESPACE = 'AWS/Lambda';
const FUNCTION_NAME_DIMENSION = 'FunctionName';
const RESOURCE_QUALIFIER_DIMENSION = 'Resource';

export class Lambda011TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = ['aws_lambda_function'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): Lambda011TfAdapter {
    return new Lambda011TfAdapter(context);
  }
}

class Lambda011TfAdapter implements Lambda011Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  hasMonitoringAlarm(): boolean {
    return this.ctx.allResources.some(resource => this.isEffectiveAlarmForAssessedFunction(resource));
  }

  private isEffectiveAlarmForAssessedFunction(resource: TerraformResource): boolean {
    if (!this.isAlarmForAssessedFunction(resource)) return false;
    if (!this.hasActionsEnabled(resource)) return false;
    return this.hasAlarmAction(resource);
  }

  /**
   * An alarm that notifies nobody is not monitoring coverage. AWS treats the two
   * ways of achieving that as separate Config rules — cloudwatch-alarm-action-check
   * (no action configured) and cloudwatch-alarm-action-enabled-check
   * (actions_enabled false) — and both are non-compliant, so both fail here.
   */
  private hasAlarmAction(alarm: TerraformResource): boolean {
    const alarmActions = alarm.values?.alarm_actions;
    return Array.isArray(alarmActions) && alarmActions.length > 0;
  }

  private isAlarmForAssessedFunction(resource: TerraformResource): boolean {
    if (!this.isLambdaNamespaceAlarm(resource)) return false;
    return this.alarmCoversAssessedFunction(resource);
  }

  private isLambdaNamespaceAlarm(resource: TerraformResource): boolean {
    if (resource.type !== CLOUDWATCH_ALARM_RESOURCE_TYPE) return false;
    return resource.values?.namespace === LAMBDA_METRIC_NAMESPACE;
  }

  private hasActionsEnabled(alarm: TerraformResource): boolean {
    return alarm.values?.actions_enabled !== false;
  }

  private alarmCoversAssessedFunction(alarm: TerraformResource): boolean {
    const dimensions = this.getAlarmDimensions(alarm);
    if (this.isScopedToSpecificVersionOrAlias(dimensions)) return false;
    if (this.providesAccountWideCoverage(dimensions)) return true;
    return this.alarmTargetsAssessedFunction(dimensions);
  }

  private getAlarmDimensions(alarm: TerraformResource): Record<string, unknown> | undefined {
    const dimensions = alarm.values?.dimensions;
    if (!dimensions || typeof dimensions !== 'object') return undefined;
    return dimensions as Record<string, unknown>;
  }

  /**
   * When alarm dimensions include a Resource qualifier (e.g., "my-function:1" or
   * "my-function:prod"), the alarm only monitors a specific published version or alias.
   * Invocations against the unqualified function or other versions/aliases are not
   * covered, so this alarm cannot satisfy the function-wide monitoring requirement.
   */
  private isScopedToSpecificVersionOrAlias(dimensions: Record<string, unknown> | undefined): boolean {
    if (!dimensions) return false;
    return RESOURCE_QUALIFIER_DIMENSION in dimensions;
  }

  private providesAccountWideCoverage(dimensions: Record<string, unknown> | undefined): boolean {
    if (!dimensions) return true;
    return !(FUNCTION_NAME_DIMENSION in dimensions);
  }

  private alarmTargetsAssessedFunction(dimensions: Record<string, unknown> | undefined): boolean {
    if (!dimensions) return false;
    const dimensionValue = dimensions[FUNCTION_NAME_DIMENSION];
    if (this.isUnresolvableAtAnalysisTime(dimensionValue)) return true;
    if (this.isAssessedFunctionNameUnresolvable()) return true;
    return this.matchesAssessedFunctionName(dimensionValue);
  }

  /**
   * In Terraform plan output, a value that cannot be resolved at analysis time (e.g.,
   * a value computed from another resource not yet created, or a reference to a variable
   * whose value is unknown) is typically rendered as null/undefined while the actual value
   * is tracked separately under after_unknown. The rule cannot prove absence of coverage
   * in this case, so it conservatively treats the alarm as potentially covering the function.
   */
  private isUnresolvableAtAnalysisTime(dimensionValue: unknown): boolean {
    return typeof dimensionValue !== 'string';
  }

  private isAssessedFunctionNameUnresolvable(): boolean {
    return this.getAssessedFunctionName() === undefined;
  }

  private matchesAssessedFunctionName(dimensionValue: unknown): boolean {
    if (typeof dimensionValue !== 'string') return false;
    return dimensionValue === this.getAssessedFunctionName();
  }

  private getAssessedFunctionName(): string | undefined {
    const functionName = this.ctx.resource.values?.function_name;
    return typeof functionName === 'string' ? functionName : undefined;
  }
}
