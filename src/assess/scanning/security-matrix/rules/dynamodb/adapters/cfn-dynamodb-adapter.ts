import { AdapterFactory, CfnContext, IacRemediation } from '../../../controls/types.js';
import { DynamodbAdapter } from './dynamodb-adapter.js';

export class CfnDynamodbAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::DynamoDB::Table'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): CfnDynamodbBoundAdapter {
    return new CfnDynamodbBoundAdapter(context);
  }
}

class CfnDynamodbBoundAdapter implements DynamodbAdapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  hasDataPlaneCoverage(): boolean {
    const trails = this.findCloudTrailTrails();
    if (trails.length === 0) return false;
    return trails.some(trail => this.trailCoversTable(trail));
  }

  getRemediation(_scenario: string): IacRemediation | null {
    return null;
  }

  private findCloudTrailTrails(): Array<Record<string, any>> {
    const resources = this.ctx.template.Resources ?? {};
    return Object.values(resources).filter(r => r.Type === 'AWS::CloudTrail::Trail');
  }

  private trailCoversTable(trail: Record<string, any>): boolean {
    const props = trail.Properties ?? {};
    if (!this.isTrailLogging(props)) return false;
    if (this.hasMatchingDataResource(props)) return true;
    if (this.hasMatchingAdvancedEventSelector(props)) return true;
    return false;
  }

  private isTrailLogging(props: Record<string, any>): boolean {
    if (props.IsLogging === true) return true;
    if (this.isUnresolvableIntrinsic(props.IsLogging)) return true;
    return false;
  }

  private isUnresolvableIntrinsic(value: any): boolean {
    if (value === null || typeof value !== 'object') return false;
    if (Array.isArray(value)) return false;
    return 'Fn::If' in value || 'Fn::ImportValue' in value;
  }

  private hasMatchingDataResource(props: Record<string, any>): boolean {
    const eventSelectors = Array.isArray(props.EventSelectors) ? props.EventSelectors : [];
    return eventSelectors.some((selector: any) => this.selectorTargetsTable(selector));
  }

  private hasMatchingAdvancedEventSelector(props: Record<string, any>): boolean {
    const advancedSelectors = Array.isArray(props.AdvancedEventSelectors) ? props.AdvancedEventSelectors : [];
    return advancedSelectors.some((selector: any) => this.advancedSelectorTargetsTable(selector));
  }

  private advancedSelectorTargetsTable(selector: any): boolean {
    const fieldSelectors = Array.isArray(selector?.FieldSelectors) ? selector.FieldSelectors : [];
    if (!this.fieldSelectorsIncludeDataCategory(fieldSelectors)) return false;
    if (!this.fieldSelectorsIncludeDynamoDbTableType(fieldSelectors)) return false;
    return this.fieldSelectorsTargetAssessedTable(fieldSelectors);
  }

  private fieldSelectorsIncludeDataCategory(fieldSelectors: any[]): boolean {
    return fieldSelectors.some(fs => fs?.Field === 'eventCategory' && this.equalsArrayIncludes(fs?.Equals, 'Data'));
  }

  private fieldSelectorsIncludeDynamoDbTableType(fieldSelectors: any[]): boolean {
    const typeSelector = fieldSelectors.find(fs => fs?.Field === 'resources.type');
    if (!typeSelector) return true;
    return this.equalsArrayIncludes(typeSelector?.Equals, 'AWS::DynamoDB::Table');
  }

  private fieldSelectorsTargetAssessedTable(fieldSelectors: any[]): boolean {
    const arnSelector = fieldSelectors.find(fs => fs?.Field === 'resources.ARN');
    if (!arnSelector) return true;
    if (this.isUnresolvableIntrinsic(arnSelector.Equals)) return true;
    const values = Array.isArray(arnSelector.Equals) ? arnSelector.Equals : [];
    if (values.some((value: any) => this.isUnresolvableIntrinsic(value))) return true;
    return values.some((value: any) => this.valueReferencesAssessedTable(value));
  }

  private equalsArrayIncludes(equals: any, target: string): boolean {
    if (!Array.isArray(equals)) return false;
    return equals.includes(target);
  }

  private selectorTargetsTable(selector: any): boolean {
    const dataResources = Array.isArray(selector?.DataResources) ? selector.DataResources : [];
    return dataResources.some((dr: any) => this.dataResourceTargetsTable(dr));
  }

  private dataResourceTargetsTable(dataResource: any): boolean {
    if (dataResource?.Type !== 'AWS::DynamoDB::Table') return false;
    if (this.isUnresolvableIntrinsic(dataResource.Values)) return true;
    const values = Array.isArray(dataResource.Values) ? dataResource.Values : [];
    if (values.some((value: any) => this.isUnresolvableIntrinsic(value))) return true;
    return values.some((value: any) => this.valueReferencesAssessedTable(value));
  }

  private valueReferencesAssessedTable(value: any): boolean {
    if (typeof value !== 'string') return false;
    if (this.matchesLogicalIdReference(value)) return true;
    if (this.matchesLiteralArn(value)) return true;
    if (this.matchesAllDynamoDbTablesPrefix(value)) return true;
    return false;
  }

  private matchesAllDynamoDbTablesPrefix(value: string): boolean {
    // Partial ARN prefix that matches all DynamoDB tables (e.g. "arn:aws:dynamodb").
    // Per AWS::CloudTrail::Trail DataResource docs, partial ARNs are supported and a
    // partial DynamoDB ARN with no specific table segment covers every table.
    const trimmed = value.trim();
    if (!/^arn:[^:]*:dynamodb(?::[^:]*)?(?::[^:]*)?\/?$/.test(trimmed)) return false;
    // Ensure no specific "table/<name>" segment is present
    return !/:table\//.test(trimmed);
  }

  private matchesLogicalIdReference(value: string): boolean {
    // After preprocessing, Fn::GetAtt [LogicalId, Arn] -> "LogicalId"
    // and Fn::Sub "${LogicalId.Arn}" -> "LogicalId.Arn"
    if (value === this.resourceId) return true;
    if (value === `${this.resourceId}.Arn`) return true;
    return false;
  }

  private matchesLiteralArn(value: string): boolean {
    const tableName = this.getAssessedTableName();
    if (!tableName) return false;
    return value.includes(`:table/${tableName}`);
  }

  private getAssessedTableName(): string | undefined {
    const name = this.ctx.resource.Properties?.TableName;
    return typeof name === 'string' ? name : undefined;
  }
}
