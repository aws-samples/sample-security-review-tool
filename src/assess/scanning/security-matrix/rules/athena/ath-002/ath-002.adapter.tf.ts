import { AdapterFactory, TerraformResource, TfContext } from '../../../controls/types.js';
import { Ath002Adapter } from './ath-002.adapter.js';
import { bucketFromOutputLocation, evaluateTlsEnforcement, TlsEnforcementVerdict } from './ath-002.policy.js';

const WORKGROUP_TYPE = 'aws_athena_workgroup';
const BUCKET_TYPE = 'aws_s3_bucket';
const BUCKET_POLICY_TYPE = 'aws_s3_bucket_policy';

type Dict = Record<string, unknown>;

export class Ath002TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = [WORKGROUP_TYPE, BUCKET_TYPE, BUCKET_POLICY_TYPE];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): Ath002TfAdapter {
    return new Ath002TfAdapter(context);
  }
}

class Ath002TfAdapter implements Ath002Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  isWorkGroup(): boolean {
    return this.resourceType === WORKGROUP_TYPE;
  }

  usesManagedQueryResultsStorage(): boolean {
    const managed = firstBlock(this.configuration()?.['managed_query_results_configuration']);
    return isEnabled(managed?.['enabled']);
  }

  /** A null output location is declared but unknown at plan time, so it counts as present. */
  hasOutputLocation(): boolean {
    const location = this.outputLocation();
    return location !== undefined && location !== '';
  }

  outputBucketEnforcesTls(): boolean {
    const location = this.outputLocation();
    if (typeof location !== 'string') return true;
    const identifiers = this.bucketIdentifiers(bucketFromOutputLocation(location));
    if (identifiers.size === 0) return true;
    return this.verdictsForBucket(identifiers).some(verdict => verdict !== 'not-enforced');
  }

  private configuration(): Dict | null {
    const values = asDict(this.ctx.resource.values);
    return firstBlock(values?.['configuration']);
  }

  private outputLocation(): unknown {
    const resultConfiguration = firstBlock(this.configuration()?.['result_configuration']);
    return resultConfiguration?.['output_location'];
  }

  /** Empty when the bucket is not part of the assessed plan, meaning its policy is unknowable. */
  private bucketIdentifiers(bucketRef: string): Set<string> {
    const identifiers = new Set<string>();
    if (!bucketRef) return identifiers;
    for (const bucket of this.resourcesOfType(BUCKET_TYPE)) {
      const name = asDict(bucket.values)?.['bucket'];
      if (bucket.address !== bucketRef && name !== bucketRef) continue;
      identifiers.add(bucketRef);
      identifiers.add(bucket.address);
      if (typeof name === 'string') identifiers.add(name);
    }
    return identifiers;
  }

  private verdictsForBucket(identifiers: Set<string>): TlsEnforcementVerdict[] {
    return this.resourcesOfType(BUCKET_POLICY_TYPE)
      .map(policy => asDict(policy.values))
      .filter(values => attachedTo(values?.['bucket'], identifiers))
      .map(values => evaluateTlsEnforcement(values?.['policy']));
  }

  private resourcesOfType(type: string): TerraformResource[] {
    return (this.ctx.allResources ?? []).filter(resource => resource?.type === type);
  }
}

function attachedTo(bucket: unknown, identifiers: Set<string>): boolean {
  return typeof bucket === 'string' && identifiers.has(bucket);
}

function asDict(value: unknown): Dict | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Dict) : null;
}

function firstBlock(value: unknown): Dict | null {
  return Array.isArray(value) ? asDict(value[0]) : asDict(value);
}

function isEnabled(value: unknown): boolean {
  return value === true || value === 'true';
}
