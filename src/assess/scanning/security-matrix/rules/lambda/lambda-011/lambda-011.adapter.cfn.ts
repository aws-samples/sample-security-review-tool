import { AdapterFactory, CfnContext, Resource, Template } from '../../../controls/types.js';
import { Lambda011Adapter } from './lambda-011.adapter.js';

const CLOUDWATCH_ALARM_RESOURCE_TYPE = 'AWS::CloudWatch::Alarm';
const LAMBDA_FUNCTION_RESOURCE_TYPE = 'AWS::Lambda::Function';
const LAMBDA_METRIC_NAMESPACE = 'AWS/Lambda';
const FUNCTION_NAME_DIMENSION = 'FunctionName';
const RESOURCE_QUALIFIER_DIMENSION = 'Resource';

interface AlarmDimension {
  readonly Name?: string;
  readonly Value?: unknown;
}

export class Lambda011CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::Lambda::Function'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): Lambda011CfnAdapter {
    return new Lambda011CfnAdapter(context);
  }
}

class Lambda011CfnAdapter implements Lambda011Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  hasMonitoringAlarm(): boolean {
    const resources = this.ctx.template.Resources ?? {};
    return Object.values(resources).some(resource => this.isEffectiveAlarmForAssessedFunction(resource));
  }

  private isEffectiveAlarmForAssessedFunction(resource: Resource): boolean {
    if (!this.isAlarmForAssessedFunction(resource)) return false;
    return this.hasActionsEnabled(resource);
  }

  private isAlarmForAssessedFunction(resource: Resource): boolean {
    if (!this.isLambdaNamespaceAlarm(resource)) return false;
    return this.alarmCoversAssessedFunction(resource);
  }

  private isLambdaNamespaceAlarm(resource: Resource): boolean {
    if (resource.Type !== CLOUDWATCH_ALARM_RESOURCE_TYPE) return false;
    return resource.Properties?.Namespace === LAMBDA_METRIC_NAMESPACE;
  }

  private hasActionsEnabled(alarm: Resource): boolean {
    return alarm.Properties?.ActionsEnabled !== false;
  }

  private alarmCoversAssessedFunction(alarm: Resource): boolean {
    const dimensions = this.getAlarmDimensions(alarm);
    if (this.isScopedToSpecificVersionOrAlias(dimensions)) return false;
    if (this.providesAccountWideCoverage(dimensions)) return true;
    return this.alarmTargetsAssessedFunction(dimensions);
  }

  private getAlarmDimensions(alarm: Resource): AlarmDimension[] {
    return alarm.Properties?.Dimensions ?? [];
  }

  /**
   * When alarm dimensions include a Resource qualifier (e.g., "my-function:1" or
   * "my-function:prod"), the alarm only monitors a specific published version or alias.
   * Invocations against the unqualified function or other versions/aliases are not
   * covered, so this alarm cannot satisfy the function-wide monitoring requirement.
   */
  private isScopedToSpecificVersionOrAlias(dimensions: AlarmDimension[]): boolean {
    return dimensions.some(dim => dim.Name === RESOURCE_QUALIFIER_DIMENSION);
  }

  private providesAccountWideCoverage(dimensions: AlarmDimension[]): boolean {
    return !dimensions.some(dim => dim.Name === FUNCTION_NAME_DIMENSION);
  }

  private alarmTargetsAssessedFunction(dimensions: AlarmDimension[]): boolean {
    const functionNameDimension = dimensions.find(dim => dim.Name === FUNCTION_NAME_DIMENSION);
    if (!functionNameDimension) return false;
    return this.dimensionMatchesAssessedFunction(functionNameDimension.Value);
  }

  /**
   * Determines whether the alarm's FunctionName dimension value identifies the assessed
   * Lambda function. A value can be:
   *  - a literal string: compared directly to the assessed function's FunctionName.
   *  - an intrinsic that points at a known resource in the template (Ref / Fn::GetAtt
   *    targeting a logical ID): resolved against that resource.
   *  - an intrinsic whose result cannot be determined at analysis time (Fn::ImportValue,
   *    Fn::Sub, or Ref/Fn::GetAtt targeting something other than a Lambda in the template):
   *    treated as a possible match to avoid false positives.
   */
  private dimensionMatchesAssessedFunction(dimensionValue: unknown): boolean {
    if (typeof dimensionValue === 'string') {
      return this.matchesAssessedFunctionName(dimensionValue);
    }
    if (this.isIntrinsic(dimensionValue)) {
      return this.intrinsicMatchesAssessedFunction(dimensionValue as Record<string, unknown>);
    }
    return false;
  }

  private matchesAssessedFunctionName(dimensionValue: string): boolean {
    const assessedFunctionName = this.getAssessedFunctionName();
    return assessedFunctionName !== undefined && dimensionValue === assessedFunctionName;
  }

  private intrinsicMatchesAssessedFunction(intrinsic: Record<string, unknown>): boolean {
    const referencedLogicalId = this.getReferencedLogicalId(intrinsic);
    if (referencedLogicalId === undefined) return this.isUnresolvableIntrinsic(intrinsic);
    if (referencedLogicalId === this.ctx.logicalId) return true;
    if (this.isLambdaInTemplate(referencedLogicalId)) return false;
    // The intrinsic targets a logical ID that is not a Lambda function in this template;
    // its resolved value cannot be determined here, so coverage is assumed possible.
    return true;
  }

  private getReferencedLogicalId(intrinsic: Record<string, unknown>): string | undefined {
    if (typeof intrinsic.Ref === 'string') return intrinsic.Ref;
    const getAtt = intrinsic['Fn::GetAtt'];
    if (Array.isArray(getAtt) && typeof getAtt[0] === 'string') return getAtt[0];
    return undefined;
  }

  /**
   * Intrinsics such as Fn::ImportValue, Fn::Sub, or Fn::Join produce values that depend
   * on data outside the template (exports, parameters, pseudo parameters). These cannot
   * be resolved at analysis time, so the rule conservatively treats the alarm as
   * potentially covering the assessed function.
   */
  private isUnresolvableIntrinsic(_intrinsic: Record<string, unknown>): boolean {
    return true;
  }

  private isLambdaInTemplate(logicalId: string): boolean {
    const resources: NonNullable<Template['Resources']> = this.ctx.template.Resources ?? {};
    const resource = resources[logicalId];
    return resource?.Type === LAMBDA_FUNCTION_RESOURCE_TYPE;
  }

  private isIntrinsic(value: unknown): boolean {
    return typeof value === 'object' && value !== null;
  }

  private getAssessedFunctionName(): string | undefined {
    const functionName = this.ctx.resource.Properties?.FunctionName;
    return typeof functionName === 'string' ? functionName : undefined;
  }
}
