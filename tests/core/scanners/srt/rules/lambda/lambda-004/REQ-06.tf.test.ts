import { describe, it, expect } from 'vitest';
import { lambda004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.control.js';
import { Lambda004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-06: Lambda function tracing mode value depends on an unresolvable condition.
 *
 * In Terraform plan output, an attribute whose value depends on resources/values not
 * yet known at plan time appears as `null` in `values` and is reported in
 * `after_unknown` (or simply absent/unresolved). When the tracing mode cannot be
 * determined, the rule must not flag the resource to avoid false positives.
 */
describe('LAMBDA-004 REQ-06 (TF): unresolvable tracing mode value should not be flagged', () => {
  const factory = new Lambda004TfAdapterFactory();

  it('does NOT flag aws_lambda_function whose tracing_config.mode is unknown at plan time', () => {
    // Simulate Terraform plan where tracing_config.mode is not resolvable
    // (e.g. it depends on a variable that references another resource attribute
    // that won't be known until apply). The mode value here represents an
    // unresolved sentinel rather than a literal string.
    const resource: TerraformResource = {
      address: 'aws_lambda_function.my_fn',
      type: 'aws_lambda_function',
      name: 'my_fn',
      provider_name: 'registry.terraform.io/hashicorp/aws',
      values: {
        function_name: 'my-fn',
        runtime: 'nodejs20.x',
        handler: 'index.handler',
        role: 'arn:aws:iam::123456789012:role/lambda-role',
        tracing_config: [
          {
            // Unresolved/unknown at plan time — represented as an object that
            // is not the literal string 'Active'.
            mode: { __unknown__: true },
          },
        ],
      },
    } as unknown as TerraformResource;

    const context: TfContext = {
      projectName: 'test-project',
      resource,
      allResources: [resource],
    };

    const adapter = factory.bind(context);
    const result = lambda004Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('does NOT flag aws_lambda_function whose tracing_config block itself is unknown at plan time', () => {
    // The entire tracing_config block is unknown — Terraform may surface this
    // as a non-array placeholder rather than the resolved list of blocks.
    const resource: TerraformResource = {
      address: 'aws_lambda_function.my_fn',
      type: 'aws_lambda_function',
      name: 'my_fn',
      provider_name: 'registry.terraform.io/hashicorp/aws',
      values: {
        function_name: 'my-fn',
        runtime: 'nodejs20.x',
        handler: 'index.handler',
        role: 'arn:aws:iam::123456789012:role/lambda-role',
        tracing_config: { __unknown__: true },
      },
    } as unknown as TerraformResource;

    const context: TfContext = {
      projectName: 'test-project',
      resource,
      allResources: [resource],
    };

    const adapter = factory.bind(context);
    const result = lambda004Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
