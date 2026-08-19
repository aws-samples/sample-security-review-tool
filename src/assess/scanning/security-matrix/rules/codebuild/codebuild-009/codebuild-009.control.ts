import { SecurityControl } from '../../../controls/security-control.js';
import type { Finding } from '../../../controls/types.js';
import type { Codebuild009Adapter } from './codebuild-009.adapter.js';

const FINDINGS = {
  MISSING_BUCKET_INSPECTION_PERMISSIONS: {
    issue: (adapter: Codebuild009Adapter) =>
      `The service role used by build project '${adapter.resourceId}' does not effectively allow both the get-bucket-ACL and get-bucket-location permissions on the associated S3 bucket(s): ${adapter.bucketsMissingRequiredPermissions().join(', ')}.`,
    remediation:
      'Grant the build project\'s service role an allow permission for both the get-bucket-ACL and the get-bucket-location actions on every S3 bucket the project uses, and remove any statement that denies either of those actions on those buckets.',
  },
} as const satisfies Record<string, Finding<Codebuild009Adapter>>;

type FindingKey = keyof typeof FINDINGS;

export class Codebuild009Control extends SecurityControl<Codebuild009Adapter, FindingKey> {
  constructor() {
    super({
      id: 'CODEBUILD-009',
      priority: 'HIGH',
      description: 'CodeBuild project service roles must include both the s3:GetBucketAcl and s3:GetBucketLocation permissions for any S3 bucket associated with the project.',
      findings: FINDINGS,
    });
  }

  protected evaluate(adapter: Codebuild009Adapter): FindingKey | null {
    const nonCompliantBuckets = adapter.bucketsMissingRequiredPermissions();
    return nonCompliantBuckets.length > 0 ? 'MISSING_BUCKET_INSPECTION_PERMISSIONS' : null;
  }
}

export const codebuild009Control = new Codebuild009Control();
