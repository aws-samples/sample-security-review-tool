import { SecurityControl } from '../../../controls/security-control.js';
import type { Finding } from '../../../controls/types.js';
import type { Ath002Adapter } from './ath-002.adapter.js';
import { s3001Control } from '../../s3/s3-001/s3-001.control.js';
import { s3008Control } from '../../s3/s3-008/s3-008.control.js';

const MISSING_OUTPUT_LOCATION = 'missing-output-location';
const OUTPUT_BUCKET_ALLOWS_INSECURE_TRANSPORT = 'output-bucket-allows-insecure-transport';

const FINDINGS = {
  [MISSING_OUTPUT_LOCATION]: {
    issue: 'Athena workgroup defines no query-result output location, so no results bucket can be identified and the results cannot be shown to be protected by a policy denying non-TLS requests',
    remediation: 'Configure the Athena workgroup to write query results to a specific S3 bucket location, and ensure that bucket is governed by a bucket policy that denies any request not using TLS.',
  },
  [OUTPUT_BUCKET_ALLOWS_INSECURE_TRANSPORT]: {
    issue: 'The S3 bucket receiving Athena query results is not protected by a policy that denies requests made without TLS',
    remediation: 'Attach a bucket policy to the Athena query-results bucket that denies all requests made without TLS, so query results can only be transferred over encrypted connections.',
  },
} as const satisfies Record<string, Finding>;

type FindingKey = keyof typeof FINDINGS;

export class Ath002Control extends SecurityControl<Ath002Adapter, FindingKey> {
  constructor() {
    super({
      id: 'ATH-002',
      priority: 'HIGH',
      description: 'Athena WorkGroups must use an S3 output location bucket whose bucket policy includes a Deny statement enforcing HTTPS/TLS (aws:SecureTransport) for all requests',
      findings: FINDINGS,
      relatedRules: [s3001Control, s3008Control],
    });
  }

  protected evaluate(adapter: Ath002Adapter): FindingKey | null {
    if (!adapter.isWorkGroup()) return null;
    if (adapter.usesManagedQueryResultsStorage()) return null;

    if (!adapter.hasOutputLocation()) return MISSING_OUTPUT_LOCATION;

    if (!adapter.outputBucketEnforcesTls()) return OUTPUT_BUCKET_ALLOWS_INSECURE_TRANSPORT;

    return null;
  }
}

export const ath002Control = new Ath002Control();
