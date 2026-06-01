import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { Cf006Adapter, S3OriginWithoutAccessControl } from './cf-006.adapter.js';
import { s3001Control } from '../../s3/s3-001/s3-001.control.js';
import { s3008Control } from '../../s3/s3-008/s3-008.control.js';

const S3_ORIGIN_ISSUE =
  'CloudFront distribution has an S3 bucket origin with no access control mechanism, ' +
  'allowing direct public access to the bucket and bypassing the distribution.';

const NON_S3_OAC_ELIGIBLE_ISSUE =
  'CloudFront distribution has an OAC-eligible non-S3 origin (such as a Lambda function URL, ' +
  'MediaStore, or MediaPackage v2 origin) with no origin access control attached, ' +
  'allowing the origin to be reached directly and bypassing the distribution.';

export class Cf006Control extends SecurityControl<Cf006Adapter> {
  constructor() {
    super({
      id: 'CF-006',
      priority: 'HIGH',
      description: 'CloudFront distributions must enable origin access control',
      remediationScenarios: [
        {
          scenario: 'S3_ORIGIN_WITHOUT_ACCESS_CONTROL',
          intent:
            'Restrict the S3 origin so that only the CloudFront distribution can read objects from the bucket, ' +
            'using an origin access control association on the distribution origin and a bucket policy that only ' +
            'allows that distribution to read.',
        },
        {
          scenario: 'NON_S3_OAC_ELIGIBLE_ORIGIN_WITHOUT_ACCESS_CONTROL',
          intent:
            'Attach an origin access control to every OAC-eligible non-S3 origin (Lambda function URL, MediaStore, ' +
            'or MediaPackage v2) on the distribution and configure the origin to require requests signed by that ' +
            'distribution, so the origin cannot be reached directly outside CloudFront.',
        },
      ],
    
      relatedRules: [s3001Control, s3008Control],
    });
  }

  protected evaluate(adapter: Cf006Adapter): ControlFinding | null {
    const unprotectedOrigins = adapter.findS3OriginsWithoutAccessControl();
    if (unprotectedOrigins.length === 0) return null;
    if (this.hasS3Origin(unprotectedOrigins)) {
      return {
        scenario: 'S3_ORIGIN_WITHOUT_ACCESS_CONTROL',
        issue: S3_ORIGIN_ISSUE,
      };
    }
    return {
      scenario: 'NON_S3_OAC_ELIGIBLE_ORIGIN_WITHOUT_ACCESS_CONTROL',
      issue: NON_S3_OAC_ELIGIBLE_ISSUE,
    };
  }

  private hasS3Origin(origins: S3OriginWithoutAccessControl[]): boolean {
    return origins.some(origin => origin.originType === 's3');
  }
}

export const cf006Control = new Cf006Control();
