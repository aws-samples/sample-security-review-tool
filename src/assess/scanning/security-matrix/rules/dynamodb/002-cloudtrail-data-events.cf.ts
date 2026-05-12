import { BaseRule, CloudFormationResource, Resource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { Template } from 'cloudform-types';
/**
 * DDB-002: DynamoDB tables must have CloudTrail data plane event logging
 * enabled.
 *
 * Performs template-aware evaluation by scanning all
 * `AWS::CloudTrail::Trail` resources in the same template to determine
 * whether at least one active trail captures data events for the assessed
 * `AWS::DynamoDB::Table` resource. Resolves CloudFormation intrinsics
 * (e.g., `!Ref`, `!GetAtt`) to their logical ID strings during evaluation
 * and treats unresolvable intrinsics conservatively to avoid false
 * positives.
 *
 * Checks:
 * - At least one trail has a basic `EventSelector` with a `DataResource`
 *   of type `AWS::DynamoDB::Table` whose `Values` array is non-empty and
 *   covers the assessed table — matched by logical ID, a wildcard ARN
 *   pattern (`arn:aws:dynamodb*`), or an unresolvable intrinsic (treated
 *   as potentially covering).
 * - OR at least one trail has an `AdvancedEventSelector` whose
 *   `FieldSelectors` contain both `eventCategory=Data` and
 *   `resources.type=AWS::DynamoDB::Table`, with no `resources.ARN
 *   NotEquals` entry that explicitly excludes the assessed table.
 * - The qualifying trail has `IsLogging` explicitly set to `true`; an
 *   absent or `false` value is treated as not-enabled. An unresolvable
 *   intrinsic for `IsLogging` is treated as potentially `true` to avoid
 *   false positives.
 *
 * Resolves CloudFormation references by matching logical IDs produced
 * after template preprocessing (e.g., `!GetAtt MyTable.Arn` and
 * `!Ref MyTable` both resolve to the string `"MyTable"`), enabling
 * accurate per-table ARN matching in both selector types.
 *
 * Known limitations:
 * - CloudTrail trails defined in other stacks or templates are not
 *   visible; only resources within the same synthesized template are
 *   inspected.
 * - Organization-level trails and account-level trails configured outside
 *   CloudFormation cannot be detected.
 * - `Fn::If` conditions with unknown runtime values leave `IsLogging`
 *   and ARN fields unresolvable; these are handled conservatively and
 *   may suppress findings that would be valid at deploy time.
 * - Cross-stack `Fn::ImportValue` references for trail properties cannot
 *   be resolved and are treated as potentially-covering/potentially-true.
 *
 * @evaluated 2026-05-12
 */
export class Ddb002Rule extends BaseRule {
  private readonly fixPrompt = `Enable CloudTrail logging for DynamoDB data plane events for this table.

Steps:
1. If no CloudTrail Trail exists, create one. It needs an S3 bucket for logs. Create a dedicated access-logging bucket (BlockPublicAccess.BLOCK_ALL, enforceSSL: true), then create the trail bucket with that as its serverAccessLogsBucket (prefix 'cloudtrail-logs/'). If an existing access-logging bucket is already in the template, reuse it.
2. Add an EventSelector to the trail with DataResources containing type 'AWS::DynamoDB::Table' and this table's ARN in Values. Set ReadWriteType to 'All'.
3. Ensure the trail has IsLogging set to true so that events are actually captured.

For CDK: The L2 Trail construct does NOT support adding DynamoDB data event selectors directly (no DataResourceType.DYNAMODB_TABLE). You MUST use the L1 escape hatch after creating the trail:
  const cfnTrail = trail.node.defaultChild as cloudtrail.CfnTrail;
  cfnTrail.eventSelectors = [{ dataResources: [{ type: 'AWS::DynamoDB::Table', values: [table.tableArn] }], readWriteType: 'All' }];

IMPORTANT: Do NOT set objectOwnership on S3 buckets — the CDK default handles ACLs correctly for server access logging. Do NOT use trail.logAllS3DataEvents() or similar L2 methods.`
  
  constructor() {
    super(
      'DDB-002',
      'HIGH',
      'DynamoDB data plane events must be captured by CloudTrail logging',
      ['AWS::DynamoDB::Table']
    );
  }

  public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null {
    if (!this.appliesTo(resource.Type) || !resource.Properties) return null;

    // Find the logical ID of the assessed resource within the template so we
    // can detect AdvancedEventSelectors that explicitly exclude this table by
    // its resolved ARN reference (which becomes the logical ID string after
    // intrinsic resolution), and so we can confirm that basic EventSelectors
    // actually list this table's ARN (rather than only listing other tables).
    const tableLogicalId = Object.entries(template.Resources || {})
      .find(([_, r]) => r === resource)?.[0];

    const hasTrailCoverage = Object.entries(template.Resources || {}).some(([_, r]) => r.Type === 'AWS::CloudTrail::Trail' && this.isTrailLogging(r) && this.hasDynamoDBDataEvents(r, tableLogicalId));

    if (!hasTrailCoverage) {
      return this.createResult(stackName, template, resource, this.description, this.fixPrompt);
    }

    return null;
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    return null;
  }

  /**
   * Check if a trail has IsLogging set to true (or to an unresolvable
   * intrinsic, in which case the value is unknowable and we avoid a false
   * positive by treating it as potentially enabled).
   *
   * An absent or explicitly-false IsLogging is treated as not-enabled.
   */
  private isTrailLogging(trail: Resource): boolean {
    const isLogging = trail.Properties?.IsLogging;
    if (isLogging === true) return true;
    // Unresolvable intrinsics (Fn::If with unknown condition, Fn::ImportValue)
    // remain as objects after preprocessing. Treat them as potentially-true to
    // avoid false positives when the actual value cannot be determined.
    if (this.isUnresolvableIntrinsic(isLogging)) return true;
    return false;
  }

  /**
   * Detect whether a value is an unresolved CloudFormation intrinsic object
   * (e.g., { "Fn::If": [...] } or { "Fn::ImportValue": "..." }). These remain
   * as objects after the template preprocessor runs.
   */
  private isUnresolvableIntrinsic(value: unknown): boolean {
    if (value === null || typeof value !== 'object') return false;
    const keys = Object.keys(value as Record<string, unknown>);
    return keys.some(k => k === 'Ref' || k.startsWith('Fn::'));
  }

  /**
   * Check if a CloudTrail trail has DynamoDB data events configured
   * via either basic EventSelectors or AdvancedEventSelectors
   */
  private hasDynamoDBDataEvents(trail: Resource, tableLogicalId?: string): boolean {
    return this.hasBasicEventSelectorForDynamoDB(trail, tableLogicalId) || this.hasAdvancedEventSelectorForDynamoDB(trail, tableLogicalId);
  }

  /**
   * Check basic EventSelectors for DynamoDB data events that cover the
   * assessed table.
   *
   * A basic EventSelector covers the assessed table when its DataResources
   * contains a DynamoDB entry whose Values include any of:
   * - The assessed table's logical ID (what !GetAtt Table.Arn / !Ref Table
   *   resolve to after preprocessing).
   * - A wildcard ARN pattern that would match all DynamoDB tables (e.g.,
   *   "arn:aws:dynamodb:*" or "arn:aws:dynamodb").
   * - An unresolvable intrinsic (object) — treated conservatively as
   *   potentially covering to avoid false positives.
   *
   * Values that are concrete strings referencing only other tables (i.e., do
   * not include the assessed table's logical ID and are not wildcards) do
   * NOT provide coverage for this table.
   */
  private hasBasicEventSelectorForDynamoDB(trail: Resource, tableLogicalId?: string): boolean {
    const eventSelectors = trail.Properties?.EventSelectors;

    if (!Array.isArray(eventSelectors)) {
      return false;
    }

    return eventSelectors.some(selector => {
      const dataResources = selector.DataResources;

      if (!Array.isArray(dataResources)) {
        return false;
      }

      return dataResources.some(dataResource => {
        // Must be DynamoDB type
        if (dataResource.Type !== 'AWS::DynamoDB::Table') {
          return false;
        }

        // Must have values (ARNs)
        const values = dataResource.Values;
        if (!Array.isArray(values) || values.length === 0) {
          return false;
        }

        // At least one value must cover the assessed table.
        return values.some(v => this.valueCoversTable(v, tableLogicalId));
      });
    });
  }

  /**
   * Determine whether a single Values entry from a DynamoDB DataResource
   * covers the assessed table.
   *
   * - Unresolvable intrinsics: treated as potentially-covering.
   * - Strings: cover if they include the assessed table's logical ID, or if
   *   they are a wildcard ARN that matches all DynamoDB tables.
   * - Without a known logical ID, fall back to the prior behavior of
   *   accepting any non-empty value.
   */
  private valueCoversTable(value: unknown, tableLogicalId?: string): boolean {
    if (this.isUnresolvableIntrinsic(value)) return true;

    if (typeof value !== 'string') {
      // Unknown shape — be conservative and treat as covering.
      return true;
    }

    // If we don't know the assessed table's logical ID, we cannot make a
    // specific determination; preserve previous permissive behavior.
    if (!tableLogicalId) return true;

    // Direct logical ID match (post intrinsic resolution).
    if (value.includes(tableLogicalId)) return true;

    // Wildcard ARN patterns covering all DynamoDB tables.
    // Examples: "arn:aws:dynamodb", "arn:aws:dynamodb:*",
    // "arn:aws:dynamodb:*:*:table/*".
    if (/^arn:aws:dynamodb(:|$)/.test(value) && value.includes('*')) return true;
    if (value === 'arn:aws:dynamodb') return true;

    return false;
  }

  /**
   * Check AdvancedEventSelectors for DynamoDB data events.
   * A valid advanced selector for DynamoDB data events must have:
   * - eventCategory Equals "Data"
   * - resources.type Equals "AWS::DynamoDB::Table"
   *
   * If a resources.ARN NotEquals is present and explicitly excludes the
   * assessed table (matched by its logical ID — which is what !GetAtt
   * Table.Arn / !Ref resolve to after preprocessing), the selector does
   * not cover this table.
   */
  private hasAdvancedEventSelectorForDynamoDB(trail: Resource, tableLogicalId?: string): boolean {
    const advancedSelectors = trail.Properties?.AdvancedEventSelectors;

    if (!Array.isArray(advancedSelectors)) {
      return false;
    }

    return advancedSelectors.some(selector => {
      const fieldSelectors = selector.FieldSelectors;

      if (!Array.isArray(fieldSelectors)) {
        return false;
      }

      let hasDataCategory = false;
      let hasDynamoDBResourceType = false;
      let excludesThisTable = false;

      for (const field of fieldSelectors) {
        const fieldName = field.Field;
        const equalsValues = field.Equals;

        if (fieldName === 'eventCategory' && Array.isArray(equalsValues) && equalsValues.includes('Data')) {
          hasDataCategory = true;
        }

        if (fieldName === 'resources.type' && Array.isArray(equalsValues) && equalsValues.includes('AWS::DynamoDB::Table')) {
          hasDynamoDBResourceType = true;
        }

        // Detect explicit exclusion of this table's ARN via NotEquals.
        // After intrinsic resolution, !GetAtt MyTable.Arn / !Ref MyTable
        // become the logical ID string "MyTable".
        if (fieldName === 'resources.ARN' && tableLogicalId) {
          const notEqualsValues = field.NotEquals;
          if (Array.isArray(notEqualsValues) && notEqualsValues.some(v => typeof v === 'string' && v.includes(tableLogicalId))) {
            excludesThisTable = true;
          }
        }
      }

      return hasDataCategory && hasDynamoDBResourceType && !excludesThisTable;
    });
  }
}

export default new Ddb002Rule();
