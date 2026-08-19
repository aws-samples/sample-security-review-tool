import { AdapterFactory, TerraformResource, TfContext } from '../../../controls/types.js';
import { isUnresolved } from '../../../terraform-rule-base.js';
import { Codebuild009Adapter } from './codebuild-009.adapter.js';
import { PIPELINE_ARTIFACT_BUCKET } from './codebuild-009.buckets.js';
import {
  PolicyStatement,
  bucketNameFromLocation,
  isRecord,
  parsePolicyDocument,
  statementsAllowRequiredActions,
  toArray,
} from './codebuild-009.iam.js';

const PROJECT_TYPE = 'aws_codebuild_project';
const DISABLED = 'DISABLED';
const PIPELINE = 'CODEPIPELINE';

function logDeliveryDisabled(status: unknown): boolean {
  return typeof status === 'string' && status.toUpperCase() === DISABLED;
}

function blockType(block: Record<string, unknown>): string {
  return String(block['type']).toUpperCase();
}

function stringValue(resource: TerraformResource | undefined, field: string): string | undefined {
  const value = (resource?.values as Record<string, unknown> | undefined)?.[field];
  return typeof value === 'string' ? value : undefined;
}

export class Codebuild009TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = ['aws_codebuild_project', 'aws_iam_role', 'aws_iam_role_policy', 'aws_iam_policy', 'aws_iam_role_policy_attachment', 'aws_iam_policy_document'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): Codebuild009TfAdapter {
    return new Codebuild009TfAdapter(context);
  }
}

class Codebuild009TfAdapter implements Codebuild009Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  bucketsMissingRequiredPermissions(): string[] {
    if (this.resourceType !== PROJECT_TYPE) return [];
    const buckets = this.associatedBuckets();
    if (buckets.length === 0) return [];
    const aliases = this.serviceRoleAliases();
    if (aliases === null) return [];
    const statements = this.statementsForRole(aliases);
    return buckets.filter(bucket => !statementsAllowRequiredActions(statements, bucket));
  }

  private get values(): Record<string, unknown> {
    const values = this.ctx.resource.values as unknown;
    return isRecord(values) ? values : {};
  }

  private ioBlocks(): Record<string, unknown>[] {
    const values = this.values;
    return [
      ...toArray(values['artifacts']),
      ...toArray(values['secondary_artifacts']),
      ...toArray(values['source']),
      ...toArray(values['secondary_sources']),
      ...toArray(values['cache']),
    ].filter(isRecord);
  }

  private associatedBuckets(): string[] {
    const blocks = this.ioBlocks();
    const locations = blocks
      .filter(block => blockType(block) === 'S3')
      .map(block => block['location']);
    locations.push(this.s3LogsLocation());

    const buckets = locations
      .filter(location => !isUnresolved(location))
      .map(bucketNameFromLocation)
      .filter((bucket): bucket is string => bucket !== null);

    if (blocks.some(block => blockType(block) === PIPELINE)) {
      buckets.push(PIPELINE_ARTIFACT_BUCKET);
    }
    return [...new Set(buckets)];
  }

  private s3LogsLocation(): unknown {
    const logsConfig = toArray(this.values['logs_config']).filter(isRecord)[0];
    if (!logsConfig) return undefined;
    const s3Logs = toArray(logsConfig['s3_logs']).filter(isRecord)[0];
    if (!s3Logs) return undefined;
    if (logDeliveryDisabled(s3Logs['status'])) return undefined;
    return s3Logs['location'];
  }

  /**
   * Every identifier that can denote the project's service role, or null when
   * the identifier itself is unknown.
   */
  private serviceRoleAliases(): string[] | null {
    const serviceRole = this.values['service_role'];
    if (typeof serviceRole !== 'string' || isUnresolved(serviceRole)) return null;
    const role = this.ctx.allResources.find(
      resource => resource.type === 'aws_iam_role' && this.identifies(resource, serviceRole),
    );
    const aliases = [serviceRole, role?.address, stringValue(role, 'name')];
    return [...new Set(aliases.filter((alias): alias is string => typeof alias === 'string'))];
  }

  private identifies(role: TerraformResource, reference: string): boolean {
    if (role.address === reference) return true;
    return stringValue(role, 'name') === reference;
  }

  private statementsForRole(aliases: string[]): PolicyStatement[] {
    const statements: PolicyStatement[] = [];
    for (const resource of this.ctx.allResources) {
      if (!this.targetsRole(resource, 'role', aliases)) continue;
      if (resource.type === 'aws_iam_role_policy') {
        statements.push(...parsePolicyDocument((resource.values as Record<string, unknown>)['policy']));
      }
      if (resource.type === 'aws_iam_role_policy_attachment') {
        statements.push(...this.attachedPolicyStatements(resource));
      }
    }
    return statements;
  }

  private targetsRole(resource: TerraformResource, field: string, aliases: string[]): boolean {
    const reference = stringValue(resource, field);
    return reference !== undefined && aliases.includes(reference);
  }

  private attachedPolicyStatements(attachment: TerraformResource): PolicyStatement[] {
    const policyArn = stringValue(attachment, 'policy_arn');
    if (policyArn === undefined) return [];
    const policy = this.ctx.allResources.find(
      resource => resource.type === 'aws_iam_policy' &&
        (resource.address === policyArn || stringValue(resource, 'name') === policyArn),
    );
    if (!policy) return [];
    return parsePolicyDocument((policy.values as Record<string, unknown>)['policy']);
  }
}
