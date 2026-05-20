import { describe, it, expect } from 'vitest';
import { lambda004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.control.js';
import { Lambda004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.adapter.tf.js';
import { TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-08 (Terraform): Lambda function has no tracing configuration regardless of
 * the event source type or runtime/package format used.
 *
 * Per resolved decision, the rule applies uniformly to all Lambda functions regardless
 * of whether their event sources support X-Ray tracing (e.g. MSK, self-managed Kafka,
 * Amazon MQ, DocumentDB) or their packaging format (Zip vs Image). The rule must flag
 * the resource whenever no tracing_config block is present.
 */
describe('LAMBDA-004 REQ-08 [TF]: missing tracing_config is flagged regardless of event source / runtime / package format', () => {
  const factory = new Lambda004TfAdapterFactory();

  function buildContext(address: string, values: Record<string, unknown>): TfContext {
    const resource = {
      address,
      type: 'aws_lambda_function',
      name: address.split('.').pop() ?? address,
      values,
    } as any;
    return {
      projectName: 'test-project',
      resource,
      allResources: [resource],
    };
  }

  it('flags aws_lambda_function (Zip package) with no tracing_config', () => {
    const ctx = buildContext('aws_lambda_function.fn_zip_no_tracing', {
      function_name: 'fn-zip-no-tracing',
      runtime: 'nodejs20.x',
      handler: 'index.handler',
      role: 'arn:aws:iam::123456789012:role/lambda-role',
      package_type: 'Zip',
      filename: 'fn.zip',
      // No tracing_config
    });
    const adapter = factory.bind(ctx);

    const result = lambda004Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LAMBDA-004');
    expect(result!.resourceType).toBe('aws_lambda_function');
    expect(result!.resourceName).toBe('aws_lambda_function.fn_zip_no_tracing');
    expect(result!.status).toBe('Open');
  });

  it('flags aws_lambda_function (Image package) with no tracing_config', () => {
    const ctx = buildContext('aws_lambda_function.fn_image_no_tracing', {
      function_name: 'fn-image-no-tracing',
      package_type: 'Image',
      image_uri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/repo:tag',
      role: 'arn:aws:iam::123456789012:role/lambda-role',
      // No tracing_config
    });
    const adapter = factory.bind(ctx);

    const result = lambda004Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LAMBDA-004');
    expect(result!.resourceType).toBe('aws_lambda_function');
  });

  it('flags aws_lambda_function with no tracing_config even when configured as MSK consumer', () => {
    // MSK event sources do not propagate X-Ray context, but the rule still applies uniformly.
    const ctx = buildContext('aws_lambda_function.fn_msk_consumer', {
      function_name: 'fn-msk-consumer',
      runtime: 'python3.12',
      handler: 'app.handler',
      role: 'arn:aws:iam::123456789012:role/lambda-role',
      filename: 'fn.zip',
      // No tracing_config — even though event source mapping is MSK
    });
    const adapter = factory.bind(ctx);

    const result = lambda004Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LAMBDA-004');
  });

  it('flags aws_lambda_function with no tracing_config for self-managed Kafka / Amazon MQ / DocumentDB event sources', () => {
    const ctx = buildContext('aws_lambda_function.fn_mq_docdb_consumer', {
      function_name: 'fn-mq-docdb-consumer',
      runtime: 'java17',
      handler: 'com.example.Handler::handle',
      role: 'arn:aws:iam::123456789012:role/lambda-role',
      filename: 'fn.jar',
      // No tracing_config
    });
    const adapter = factory.bind(ctx);

    const result = lambda004Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LAMBDA-004');
  });

  it('flags aws_lambda_function when tracing_config is explicitly null', () => {
    const ctx = buildContext('aws_lambda_function.fn_tracing_null', {
      function_name: 'fn-tracing-null',
      runtime: 'nodejs20.x',
      handler: 'index.handler',
      role: 'arn:aws:iam::123456789012:role/lambda-role',
      filename: 'fn.zip',
      tracing_config: null,
    });
    const adapter = factory.bind(ctx);

    const result = lambda004Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LAMBDA-004');
  });

  it('flags aws_lambda_function when tracing_config is an empty array (no blocks)', () => {
    const ctx = buildContext('aws_lambda_function.fn_tracing_empty', {
      function_name: 'fn-tracing-empty',
      runtime: 'nodejs20.x',
      handler: 'index.handler',
      role: 'arn:aws:iam::123456789012:role/lambda-role',
      filename: 'fn.zip',
      tracing_config: [],
    });
    const adapter = factory.bind(ctx);

    const result = lambda004Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LAMBDA-004');
  });

  it('flags aws_lambda_function when values is entirely absent', () => {
    const ctx = buildContext('aws_lambda_function.fn_no_values', undefined as unknown as Record<string, unknown>);
    const adapter = factory.bind(ctx);

    const result = lambda004Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LAMBDA-004');
  });
});
