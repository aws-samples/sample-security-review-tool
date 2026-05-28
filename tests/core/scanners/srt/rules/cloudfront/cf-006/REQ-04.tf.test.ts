import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.tf.js';
import { TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

function buildContext(values: any): TfContext {
  const resource: any = {
    address: 'aws_cloudfront_distribution.example',
    type: 'aws_cloudfront_distribution',
    name: 'example',
    values,
  };
  return {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
}

describe('CF-006 TF: S3 origin with empty/unset origin_access_control_id', () => {
  it('flags an S3 origin whose origin_access_control_id is an empty string', () => {
    const context = buildContext({
      origin: [
        {
          origin_id: 's3-origin-empty-oac',
          domain_name: 'my-bucket.s3.us-east-1.amazonaws.com',
          origin_access_control_id: '',
          s3_origin_config: [
            { origin_access_identity: '' },
          ],
        },
      ],
    });

    const factory = new Cf006TfAdapterFactory();
    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-006');
    expect(result?.resourceType).toBe('aws_cloudfront_distribution');
    expect(result?.resourceName).toBe('aws_cloudfront_distribution.example');
    expect(adapter.unprotectedS3Origins).toHaveLength(1);
    expect(adapter.unprotectedS3Origins[0].originId).toBe('s3-origin-empty-oac');
  });

  it('flags an S3 origin where origin_access_control_id is omitted entirely', () => {
    const context = buildContext({
      origin: [
        {
          origin_id: 's3-origin-no-oac',
          domain_name: 'my-bucket.s3.us-east-1.amazonaws.com',
          s3_origin_config: [
            { origin_access_identity: '' },
          ],
        },
      ],
    });

    const factory = new Cf006TfAdapterFactory();
    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-006');
    expect(adapter.unprotectedS3Origins).toHaveLength(1);
    expect(adapter.unprotectedS3Origins[0].originId).toBe('s3-origin-no-oac');
  });

  it('flags an S3 origin where origin_access_control_id is null', () => {
    const context = buildContext({
      origin: [
        {
          origin_id: 's3-origin-null-oac',
          domain_name: 'my-bucket.s3.us-east-1.amazonaws.com',
          origin_access_control_id: null,
          s3_origin_config: [
            { origin_access_identity: '' },
          ],
        },
      ],
    });

    const factory = new Cf006TfAdapterFactory();
    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(adapter.unprotectedS3Origins).toHaveLength(1);
    expect(adapter.unprotectedS3Origins[0].originId).toBe('s3-origin-null-oac');
  });
});
