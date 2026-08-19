import { AdapterFactory, CfnContext, Resource } from '../../../controls/types.js';
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

const PROJECT_TYPE = 'AWS::CodeBuild::Project';
const DISABLED = 'DISABLED';
const PIPELINE = 'CODEPIPELINE';

function logDeliveryDisabled(status: unknown): boolean {
  return typeof status === 'string' && status.toUpperCase() === DISABLED;
}

function isPipelineManaged(type: unknown): boolean {
  return typeof type === 'string' && type.toUpperCase() === PIPELINE;
}

export class Codebuild009CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::CodeBuild::Project', 'AWS::IAM::Role', 'AWS::IAM::Policy', 'AWS::IAM::ManagedPolicy'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): Codebuild009CfnAdapter {
    return new Codebuild009CfnAdapter(context);
  }
}

class Codebuild009CfnAdapter implements Codebuild009Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  bucketsMissingRequiredPermissions(): string[] {
    if (this.resourceType !== PROJECT_TYPE) return [];
    const buckets = this.associatedBuckets();
    if (buckets.length === 0) return [];
    const roleReference = this.serviceRoleReference();
    if (roleReference === null) return [];
    const statements = this.statementsForRole(roleReference);
    return buckets.filter(bucket => !statementsAllowRequiredActions(statements, bucket));
  }

  private get properties(): Record<string, unknown> {
    const props = (this.ctx.resource as { Properties?: unknown }).Properties;
    return isRecord(props) ? props : {};
  }

  private ioEntries(): Record<string, unknown>[] {
    const props = this.properties;
    return [
      ...toArray(props['Artifacts']),
      ...toArray(props['SecondaryArtifacts']),
      ...toArray(props['Source']),
      ...toArray(props['SecondarySources']),
      ...toArray(props['Cache']),
    ].filter(isRecord);
  }

  private associatedBuckets(): string[] {
    const entries = this.ioEntries();
    const locations = entries
      .filter(entry => entry['Type'] === 'S3')
      .map(entry => entry['Location']);
    locations.push(this.s3LogsLocation());

    const buckets = locations
      .map(bucketNameFromLocation)
      .filter((bucket): bucket is string => bucket !== null);

    if (entries.some(entry => isPipelineManaged(entry['Type']))) {
      buckets.push(PIPELINE_ARTIFACT_BUCKET);
    }
    return [...new Set(buckets)];
  }

  private s3LogsLocation(): unknown {
    const logs = this.properties['LogsConfig'];
    if (!isRecord(logs)) return undefined;
    const s3Logs = logs['S3Logs'];
    if (!isRecord(s3Logs)) return undefined;
    if (logDeliveryDisabled(s3Logs['Status'])) return undefined;
    return s3Logs['Location'];
  }

  /**
   * The identifier the project uses for its service role, or null when the
   * identifier itself is unknown (an unresolved intrinsic).
   */
  private serviceRoleReference(): string | null {
    const serviceRole = this.properties['ServiceRole'];
    return typeof serviceRole === 'string' ? serviceRole : null;
  }

  private statementsForRole(roleId: string): PolicyStatement[] {
    const statements: PolicyStatement[] = [...this.inlineRoleStatements(roleId)];
    for (const resource of Object.values(this.resources())) {
      if (resource.Type !== 'AWS::IAM::Policy' && resource.Type !== 'AWS::IAM::ManagedPolicy') continue;
      const props = isRecord((resource as { Properties?: unknown }).Properties) ? (resource as any).Properties : {};
      if (!toArray(props['Roles']).includes(roleId)) continue;
      statements.push(...parsePolicyDocument(props['PolicyDocument']));
    }
    return statements;
  }

  private inlineRoleStatements(roleId: string): PolicyStatement[] {
    const role = this.resources()[roleId];
    if (!role || role.Type !== 'AWS::IAM::Role') return [];
    const props = isRecord((role as { Properties?: unknown }).Properties)
      ? ((role as any).Properties as Record<string, unknown>)
      : {};
    return toArray(props['Policies'])
      .filter(isRecord)
      .flatMap(policy => parsePolicyDocument(policy['PolicyDocument']));
  }

  private resources(): Record<string, Resource> {
    const resources = this.ctx.template.Resources;
    return (resources ?? {}) as Record<string, Resource>;
  }
}
