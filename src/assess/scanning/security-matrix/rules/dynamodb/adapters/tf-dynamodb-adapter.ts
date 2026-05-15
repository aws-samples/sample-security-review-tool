import { AdapterFactory, TfContext, IacRemediation, TerraformResource } from '../../../controls/types.js';
import { DynamodbAdapter } from './dynamodb-adapter.js';

export class TfDynamodbAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = ['aws_dynamodb_table'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): TfDynamodbBoundAdapter {
    return new TfDynamodbBoundAdapter(context);
  }
}

class TfDynamodbBoundAdapter implements DynamodbAdapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  hasDataPlaneCoverage(): boolean {
    const trails = this.findCloudTrailTrails();
    if (trails.length === 0) return false;
    return trails.some(trail => this.trailCoversTable(trail));
  }

  getRemediation(_scenario: string): IacRemediation | null {
    return null;
  }

  private findCloudTrailTrails(): TerraformResource[] {
    return this.ctx.allResources.filter(r => r.type === 'aws_cloudtrail');
  }

  private trailCoversTable(trail: TerraformResource): boolean {
    const values = trail.values ?? {};
    if (!this.isTrailLogging(values)) return false;
    if (this.hasMatchingEventSelector(values)) return true;
    if (this.hasMatchingAdvancedEventSelector(values)) return true;
    return false;
  }

  private isTrailLogging(values: Record<string, any>): boolean {
    if (this.isLoggingExplicitlyDisabled(values)) return false;
    if (this.isLoggingUnresolvable(values)) return true;
    if (this.isLoggingExplicitlyEnabled(values)) return true;
    return false;
  }

  private isLoggingExplicitlyDisabled(values: Record<string, any>): boolean {
    if (values.enable_logging === false) return true;
    if (values.is_logging === false) return true;
    return false;
  }

  private isLoggingExplicitlyEnabled(values: Record<string, any>): boolean {
    if (values.enable_logging === true) return true;
    if (values.is_logging === true) return true;
    return false;
  }

  private isLoggingUnresolvable(values: Record<string, any>): boolean {
    if (this.isUnresolvableLoggingValue(values, 'enable_logging')) return true;
    if (this.isUnresolvableLoggingValue(values, 'is_logging')) return true;
    return false;
  }

  private isUnresolvableLoggingValue(values: Record<string, any>, key: string): boolean {
    if (!(key in values)) return false;
    return values[key] === null;
  }

  private hasMatchingEventSelector(values: Record<string, any>): boolean {
    const eventSelectors = Array.isArray(values.event_selector) ? values.event_selector : [];
    return eventSelectors.some((selector: any) => this.selectorTargetsTable(selector));
  }

  private hasMatchingAdvancedEventSelector(values: Record<string, any>): boolean {
    const advancedSelectors = Array.isArray(values.advanced_event_selector) ? values.advanced_event_selector : [];
    return advancedSelectors.some((selector: any) => this.advancedSelectorTargetsTable(selector));
  }

  private advancedSelectorTargetsTable(selector: any): boolean {
    const fieldSelectors = Array.isArray(selector?.field_selector) ? selector.field_selector : [];
    if (!this.fieldSelectorsMatchDataCategory(fieldSelectors)) return false;
    if (!this.fieldSelectorsMatchDynamoDbResourceType(fieldSelectors)) return false;
    return this.fieldSelectorsMatchAssessedTableArn(fieldSelectors);
  }

  private fieldSelectorsMatchDataCategory(fieldSelectors: any[]): boolean {
    return fieldSelectors.some((fs: any) => fs?.field === 'eventCategory' && this.equalsValues(fs).includes('Data'));
  }

  private fieldSelectorsMatchDynamoDbResourceType(fieldSelectors: any[]): boolean {
    return fieldSelectors.some((fs: any) => fs?.field === 'resources.type' && this.equalsValues(fs).includes('AWS::DynamoDB::Table'));
  }

  private fieldSelectorsMatchAssessedTableArn(fieldSelectors: any[]): boolean {
    const arnSelectors = fieldSelectors.filter((fs: any) => fs?.field === 'resources.ARN');
    if (arnSelectors.length === 0) return true;
    return arnSelectors.some((fs: any) => this.arnSelectorMatchesAssessedTable(fs));
  }

  private arnSelectorMatchesAssessedTable(fs: any): boolean {
    const equals = this.equalsValues(fs);
    const startsWith = this.fieldValues(fs, 'starts_with');
    if (this.anyValueIsUnresolvable(equals) || this.anyValueIsUnresolvable(startsWith)) return true;
    if (equals.some(v => this.valueReferencesAssessedTable(v))) return true;
    if (startsWith.some(v => this.startsWithMatchesAssessedTable(v))) return true;
    return false;
  }

  private anyValueIsUnresolvable(values: any[]): boolean {
    return values.some(v => this.isUnresolvableValue(v) || this.isUnresolvableInterpolationString(v));
  }

  private isUnresolvableInterpolationString(value: any): boolean {
    if (typeof value !== 'string') return false;
    return /\$\{[^}]+\}/.test(value);
  }

  private startsWithMatchesAssessedTable(value: any): boolean {
    if (typeof value !== 'string') return false;
    const tableArn = this.getAssessedTableArn();
    if (tableArn && tableArn.startsWith(value)) return true;
    return this.matchesAllDynamoDbTablesPrefix(value);
  }

  private equalsValues(fs: any): any[] {
    return this.fieldValues(fs, 'equals');
  }

  private fieldValues(fs: any, key: string): any[] {
    const value = fs?.[key];
    return Array.isArray(value) ? value : [];
  }

  private selectorTargetsTable(selector: any): boolean {
    const dataResources = Array.isArray(selector?.data_resource) ? selector.data_resource : [];
    return dataResources.some((dr: any) => this.dataResourceTargetsTable(dr));
  }

  private dataResourceTargetsTable(dataResource: any): boolean {
    if (dataResource?.type !== 'AWS::DynamoDB::Table') return false;
    const values = Array.isArray(dataResource.values) ? dataResource.values : [];
    if (values.some((value: any) => this.isUnresolvableValue(value))) return true;
    return values.some((value: any) => this.valueReferencesAssessedTable(value));
  }

  private isUnresolvableValue(value: any): boolean {
    if (value === null || value === undefined) return false;
    if (typeof value !== 'object') return false;
    return this.hasIntrinsicMarker(value);
  }

  private hasIntrinsicMarker(value: Record<string, any>): boolean {
    const keys = Object.keys(value);
    return keys.some(key => key.startsWith('Fn::') || key === 'Ref');
  }

  private valueReferencesAssessedTable(value: any): boolean {
    if (typeof value !== 'string') return false;
    if (this.matchesAssessedTableArn(value)) return true;
    if (this.matchesAllDynamoDbTablesPrefix(value)) return true;
    return false;
  }

  private matchesAssessedTableArn(value: string): boolean {
    const tableArn = this.getAssessedTableArn();
    if (tableArn && value === tableArn) return true;
    const tableName = this.getAssessedTableName();
    if (tableName && value.includes(`:table/${tableName}`)) return true;
    return false;
  }

  private matchesAllDynamoDbTablesPrefix(value: string): boolean {
    const trimmed = value.trim();
    if (!/^arn:[^:]*:dynamodb(?::[^:]*)?(?::[^:]*)?\/?$/.test(trimmed)) return false;
    return !/:table\//.test(trimmed);
  }

  private getAssessedTableArn(): string | undefined {
    const arn = this.ctx.resource.values?.arn;
    return typeof arn === 'string' ? arn : undefined;
  }

  private getAssessedTableName(): string | undefined {
    const name = this.ctx.resource.values?.name;
    return typeof name === 'string' ? name : undefined;
  }
}
