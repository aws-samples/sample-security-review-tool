import { AdapterFactory, CfnContext, IacRemediation, Resource } from '../../../controls/types.js';
import { Ddb002Adapter } from './ddb-002.adapter.js';

const CLOUDTRAIL_TYPE = 'AWS::CloudTrail::Trail';
const DYNAMODB_DATA_RESOURCE_TYPE = 'AWS::DynamoDB::Table';

export class Ddb002CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::DynamoDB::Table', 'AWS::DynamoDB::GlobalTable'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): Ddb002CfnAdapter {
    return new Ddb002CfnAdapter(context);
  }
}

class Ddb002CfnAdapter implements Ddb002Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  hasTrailCapturingDynamoDbDataEvents(): boolean {
    const resources = this.ctx.template.Resources ?? {};
    return Object.values(resources).some(resource => this.trailCoversAssessedTable(resource));
  }

  private trailCoversAssessedTable(resource: Resource): boolean {
    if (resource.Type !== CLOUDTRAIL_TYPE) return false;
    const properties = (resource.Properties ?? {}) as Record<string, unknown>;
    if (this.isLoggingExplicitlyDisabled(properties)) return false;
    return (
      this.eventSelectorsCoverAssessedTable(properties.EventSelectors) ||
      this.advancedEventSelectorsCoverAssessedTable(properties.AdvancedEventSelectors)
    );
  }

  private isLoggingExplicitlyDisabled(properties: Record<string, unknown>): boolean {
    return properties.IsLogging === false;
  }

  private eventSelectorsCoverAssessedTable(selectors: unknown): boolean {
    if (!Array.isArray(selectors)) return false;
    return selectors.some(selector => {
      const dataResources = (selector as Record<string, unknown>)?.DataResources;
      if (!Array.isArray(dataResources)) return false;
      return dataResources.some(dr => this.dataResourceCoversAssessedTable(dr));
    });
  }

  private dataResourceCoversAssessedTable(dataResource: unknown): boolean {
    const dr = dataResource as Record<string, unknown>;
    if (dr?.Type !== DYNAMODB_DATA_RESOURCE_TYPE) return false;
    const values = dr.Values;
    if (Array.isArray(values)) {
      if (values.length === 0) return false;
      return values.some(value => this.valueCoversAssessedTable(value));
    }
    return this.isUnresolvedValue(values);
  }

  private isUnresolvedValue(value: unknown): boolean {
    if (value === null || value === undefined) return false;
    return typeof value === 'object';
  }

  private valueCoversAssessedTable(value: unknown): boolean {
    if (this.isUnresolvedValue(value)) return true;
    if (typeof value !== 'string') return false;
    if (this.isWildcardArn(value)) return true;
    return this.identifierMatchesAssessedTable(value);
  }

  private advancedEventSelectorsCoverAssessedTable(selectors: unknown): boolean {
    if (!Array.isArray(selectors)) return false;
    return selectors.some(selector => this.advancedSelectorCoversAssessedTable(selector));
  }

  private advancedSelectorCoversAssessedTable(selector: unknown): boolean {
    const fieldSelectors = (selector as Record<string, unknown>)?.FieldSelectors;
    if (!Array.isArray(fieldSelectors)) return false;
    if (!this.fieldSelectorsTargetDynamoDb(fieldSelectors)) return false;
    return this.fieldSelectorsCoverAssessedTable(fieldSelectors);
  }

  private fieldSelectorsTargetDynamoDb(fieldSelectors: unknown[]): boolean {
    return fieldSelectors.some(fs => {
      const field = (fs as Record<string, unknown>)?.Field;
      const equals = (fs as Record<string, unknown>)?.Equals;
      if (field !== 'resources.type' || !Array.isArray(equals)) return false;
      return equals.some(v => v === DYNAMODB_DATA_RESOURCE_TYPE);
    });
  }

  private fieldSelectorsCoverAssessedTable(fieldSelectors: unknown[]): boolean {
    const arnSelector = fieldSelectors.find(fs => (fs as Record<string, unknown>)?.Field === 'resources.ARN');
    if (!arnSelector) return true;
    const equals = (arnSelector as Record<string, unknown>).Equals;
    if (Array.isArray(equals)) {
      if (equals.length === 0) return true;
      return equals.some(v => this.valueCoversAssessedTable(v));
    }
    return this.isUnresolvedValue(equals);
  }

  private isWildcardArn(value: string): boolean {
    return value === 'arn:aws:dynamodb' || value.endsWith(':table/*') || value === '*';
  }

  private identifierMatchesAssessedTable(value: string): boolean {
    if (value === this.resourceId) return true;
    return value.includes(`:table/${this.resourceId}`);
  }

  getRemediation(scenario: string): IacRemediation | null {
    return null;
  }
}
