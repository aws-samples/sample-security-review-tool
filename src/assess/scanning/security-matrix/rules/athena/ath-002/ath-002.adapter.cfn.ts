import { AdapterFactory, CfnContext, Resource } from '../../../controls/types.js';
import { Ath002Adapter } from './ath-002.adapter.js';
import { bucketFromOutputLocation, evaluateTlsEnforcement, TlsEnforcementVerdict } from './ath-002.policy.js';

const WORKGROUP_TYPE = 'AWS::Athena::WorkGroup';
const BUCKET_TYPE = 'AWS::S3::Bucket';
const BUCKET_POLICY_TYPE = 'AWS::S3::BucketPolicy';

type Dict = Record<string, unknown>;

export class Ath002CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = [WORKGROUP_TYPE, BUCKET_TYPE, BUCKET_POLICY_TYPE];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): Ath002CfnAdapter {
    return new Ath002CfnAdapter(context);
  }
}

class Ath002CfnAdapter implements Ath002Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  isWorkGroup(): boolean {
    return this.resourceType === WORKGROUP_TYPE;
  }

  usesManagedQueryResultsStorage(): boolean {
    const managed = asDict(this.workGroupConfiguration()?.['ManagedQueryResultsConfiguration']);
    return isEnabled(managed?.['Enabled']);
  }

  hasOutputLocation(): boolean {
    return this.outputLocation() !== undefined;
  }

  outputBucketEnforcesTls(): boolean {
    const location = this.outputLocation();
    if (typeof location !== 'string') return true;
    const identifiers = this.bucketIdentifiers(bucketFromOutputLocation(location));
    if (identifiers.size === 0) return true;
    return this.verdictsForBucket(identifiers).some(verdict => verdict !== 'not-enforced');
  }

  private workGroupConfiguration(): Dict | null {
    const properties = asDict(this.ctx.resource.Properties);
    return asDict(properties?.['WorkGroupConfiguration']);
  }

  private outputLocation(): unknown {
    const resultConfiguration = asDict(this.workGroupConfiguration()?.['ResultConfiguration']);
    return resultConfiguration?.['OutputLocation'];
  }

  /** Empty when the bucket is not declared in this template, meaning its policy is unknowable. */
  private bucketIdentifiers(bucketRef: string): Set<string> {
    const identifiers = new Set<string>();
    if (!bucketRef) return identifiers;
    for (const [logicalId, resource] of this.resourcesOfType(BUCKET_TYPE)) {
      const bucketName = asDict(resource.Properties)?.['BucketName'];
      if (logicalId !== bucketRef && bucketName !== bucketRef) continue;
      identifiers.add(bucketRef);
      identifiers.add(logicalId);
      if (typeof bucketName === 'string') identifiers.add(bucketName);
    }
    return identifiers;
  }

  private verdictsForBucket(identifiers: Set<string>): TlsEnforcementVerdict[] {
    return this.resourcesOfType(BUCKET_POLICY_TYPE)
      .map(([, resource]) => asDict(resource.Properties))
      .filter(properties => attachedTo(properties?.['Bucket'], identifiers))
      .map(properties => evaluateTlsEnforcement(properties?.['PolicyDocument']));
  }

  private resourcesOfType(type: string): [string, Resource][] {
    const resources = (this.ctx.template.Resources ?? {}) as Record<string, Resource>;
    return Object.entries(resources).filter(([, resource]) => resource?.Type === type);
  }
}

function attachedTo(bucket: unknown, identifiers: Set<string>): boolean {
  return typeof bucket === 'string' && identifiers.has(bucket);
}

function asDict(value: unknown): Dict | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Dict) : null;
}

function isEnabled(value: unknown): boolean {
  return value === true || value === 'true';
}
