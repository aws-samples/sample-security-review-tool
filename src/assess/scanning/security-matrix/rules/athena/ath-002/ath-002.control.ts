import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { Ath002Adapter } from './ath-002.adapter.js';
import { s3001Control } from '../../s3/s3-001/s3-001.control.js';
import { s3008Control } from '../../s3/s3-008/s3-008.control.js';

const MISSING_OUTPUT_LOCATION = 'missing-output-location';
const OUTPUT_BUCKET_ALLOWS_INSECURE_TRANSPORT = 'output-bucket-allows-insecure-transport';

export class Ath002Control extends SecurityControl<Ath002Adapter> {
  constructor() {
    super({
      id: 'ATH-002',
      priority: 'HIGH',
      description: 'Athena WorkGroups must use an S3 output location bucket whose bucket policy includes a Deny statement enforcing HTTPS/TLS (aws:SecureTransport) for all requests',
      remediationScenarios: [
        {
          scenario: MISSING_OUTPUT_LOCATION,
          intent: 'Configure the Athena workgroup to write query results to a specific S3 bucket location, and ensure that bucket is governed by a bucket policy that denies any request not using TLS.',
        },
        {
          scenario: OUTPUT_BUCKET_ALLOWS_INSECURE_TRANSPORT,
          intent: 'Attach a bucket policy to the Athena query-results bucket that denies all requests made without TLS, so query results can only be transferred over encrypted connections.',
        },
      ],
      relatedRules: [s3001Control, s3008Control],
    });
  }

  protected evaluate(adapter: Ath002Adapter): ControlFinding | null {
    if (!adapter.isWorkGroup()) return null;
    if (adapter.usesManagedQueryResultsStorage()) return null;

    if (!adapter.hasOutputLocation()) {
      return {
        scenario: MISSING_OUTPUT_LOCATION,
        issue: 'Athena workgroup defines no query-result output location, so no results bucket can be identified and the results cannot be shown to be protected by a policy denying non-TLS requests',
      };
    }

    if (!adapter.outputBucketEnforcesTls()) {
      return {
        scenario: OUTPUT_BUCKET_ALLOWS_INSECURE_TRANSPORT,
        issue: 'The S3 bucket receiving Athena query results is not protected by a policy that denies requests made without TLS',
      };
    }

    return null;
  }
}

export const ath002Control = new Ath002Control();
