import { AdapterFactory, TfContext, IacRemediation, TerraformResource } from '../../../controls/types.js';
import { Ddb002Adapter } from './ddb-002.adapter.js';

const CLOUDTRAIL_TYPE = 'aws_cloudtrail';
const DYNAMODB_DATA_RESOURCE_TYPE = 'AWS::DynamoDB::Table';

export class Ddb002TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = ['aws_dynamodb_table'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): Ddb002TfAdapter {
    return new Ddb002TfAdapter(context);
  }
}

class Ddb002TfAdapter implements Ddb002Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  hasTrailCapturingDynamoDbDataEvents(): boolean {
    return this.ctx.allResources.some(resource => this.trailCoversAssessedTable(resource));
  }

  private trailCoversAssessedTable(resource: TerraformResource): boolean {
    if (resource.type !== CLOUDTRAIL_TYPE) return false;
    const values = (resource.values ?? {}) as Record<string, unknown>;
    if (this.isLoggingExplicitlyDisabled(values)) return false;
    return (
      this.eventSelectorsCoverAssessedTable(values.event_selector) ||
      this.advancedEventSelectorsCoverAssessedTable(values.advanced_event_selector)
    );
  }

  private isLoggingExplicitlyDisabled(values: Record<string, unknown>): boolean {
    return values.enable_logging === false;
  }

  private eventSelectorsCoverAssessedTable(selectors: unknown): boolean {
    if (!Array.isArray(selectors)) return false;
    return selectors.some(selector => {
      const dataResources = (selector as Record<string, unknown>)?.data_resource;
      if (!Array.isArray(dataResources)) return false;
      return dataResources.some(dr => this.dataResourceCoversAssessedTable(dr));
    });
  }

  private dataResourceCoversAssessedTable(dataResource: unknown): boolean {
    const dr = dataResource as Record<string, unknown>;
    if (dr?.type !== DYNAMODB_DATA_RESOURCE_TYPE) return false;
    const values = dr.values;
    if (Array.isArray(values)) {
      if (values.length === 0) return false;
      return values.some(value => this.valueCoversAssessedTable(value));
    }
    return this.isUnresolvedValue(values);
  }

  private isUnresolvedValue(value: unknown): boolean {
    if (value === undefined) return false;
    if (value === null) return true;
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
    const fieldSelectors = (selector as Record<string, unknown>)?.field_selector;
    if (!Array.isArray(fieldSelectors)) return false;
    if (!this.fieldSelectorsTargetDynamoDb(fieldSelectors)) return false;
    return this.fieldSelectorsCoverAssessedTable(fieldSelectors);
  }

  private fieldSelectorsTargetDynamoDb(fieldSelectors: unknown[]): boolean {
    return fieldSelectors.some(fs => {
      const field = (fs as Record<string, unknown>)?.field;
      const equals = (fs as Record<string, unknown>)?.equals;
      if (field !== 'resources.type' || !Array.isArray(equals)) return false;
      return equals.some(v => v === DYNAMODB_DATA_RESOURCE_TYPE);
    });
  }

  private fieldSelectorsCoverAssessedTable(fieldSelectors: unknown[]): boolean {
    const arnSelector = fieldSelectors.find(fs => (fs as Record<string, unknown>)?.field === 'resources.ARN');
    if (!arnSelector) return true;
    const equals = (arnSelector as Record<string, unknown>).equals;
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
    const tableArn = this.assessedTableArn();
    const tableName = this.assessedTableName();
    if (tableArn && value === tableArn) return true;
    if (tableName && value.endsWith(`:table/${tableName}`)) return true;
    if (tableName && value === tableName) return true;
    return false;
  }

  private assessedTableArn(): string | null {
    const values = (this.ctx.resource.values ?? {}) as Record<string, unknown>;
    return typeof values.arn === 'string' ? values.arn : null;
  }

  private assessedTableName(): string | null {
    const values = (this.ctx.resource.values ?? {}) as Record<string, unknown>;
    return typeof values.name === 'string' ? values.name : null;
  }

  getRemediation(_scenario: string): IacRemediation | null {
    return null;
  }
}
