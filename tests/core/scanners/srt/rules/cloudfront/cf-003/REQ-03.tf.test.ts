import { describe, it, expect } from 'vitest';
import { cf003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-003/cf-003.control.js';
import { Cf003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-003/cf-003.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-003 / REQ-03 (Terraform): inline access logging with destination bucket only (no prefix) should pass', () => {
  it('returns no scan result when logging_config has bucket set and prefix omitted', () => {
    const distribution: TerraformResource = {
      address: 'aws_cloudfront_distribution.my_distribution',
      type: 'aws_cloudfront_distribution',
      name: 'my_distribution',
      provider_name: 'registry.terraform.io/hashicorp/aws',
      values: {
        enabled: true,
        logging_config: [
          {
            bucket: 'my-access-logs-bucket.s3.amazonaws.com',
            // prefix intentionally omitted - it is optional
            include_cookies: false,
          },
        ],
      },
    } as unknown as TerraformResource;

    const allResources: TerraformResource[] = [distribution];
    const factory = new Cf003TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = cf003Control.run(adapter, context);

    expect(adapter.hasAccessLogging).toBe(true);
    expect(result).toBeNull();
  });
});
