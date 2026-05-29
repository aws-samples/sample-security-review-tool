import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-07 (Terraform):
 * When a bucket's logging configuration cannot be determined at plan time —
 * for example, a separate aws_s3_bucket_logging resource exists but its
 * `bucket` field is null because the expression involved a multi-source
 * interpolation the plan reader could not collapse to a single address —
 * the rule must not flag. "Unknown" must be treated as a pass.
 */
describe('S3-001 REQ-07 (TF): unresolvable logging configuration should pass', () => {
  const factory = new S3001TfAdapterFactory();

  const buildContext = (
    resource: TerraformResource,
    allResources: TerraformResource[],
  ): TfContext => ({
    projectName: 'test-project',
    resource,
    allResources,
  });

  it('does not flag a bucket when an associated aws_s3_bucket_logging has a null/unknown bucket field', () => {
    const bucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'site',
      address: 'aws_s3_bucket.site',
      values: { bucket: 'my-site-bucket' },
    } as TerraformResource;

    // The plan reader could not collapse the `bucket` expression to a single
    // resource address, so it is recorded as null. This is the "unknown" case.
    const logging: TerraformResource = {
      type: 'aws_s3_bucket_logging',
      name: 'site',
      address: 'aws_s3_bucket_logging.site',
      values: { bucket: null, target_bucket: 'aws_s3_bucket.logs' },
    } as TerraformResource;

    const context = buildContext(bucket, [bucket, logging]);
    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('does not flag a bucket whose inline logging block value is unknown (null) at plan time', () => {
    // The `logging` argument exists in configuration but its value is unknown
    // at plan time (e.g. it depends on another resource not yet created).
    // The plan reader records the field as null.
    const bucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'site',
      address: 'aws_s3_bucket.site',
      values: { bucket: 'my-site-bucket', logging: null },
    } as TerraformResource;

    const context = buildContext(bucket, [bucket]);
    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
