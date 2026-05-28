import { describe, it, expect } from 'vitest';
import { lambda012Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.control.js';
import { Lambda012TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-012 REQ-07 (Terraform): unresolvable execution role reference', () => {
  it('passes when the role attribute is unresolvable (undefined) at analysis time', () => {
    // In a Terraform plan, an attribute that depends on a value not yet known
    // (e.g., an unresolvable runtime expression / not-yet-computed reference)
    // will not appear as a string. The adapter's getRole only returns strings,
    // so unresolvable roles are treated as "unknown" -> pass.
    const functionA: TerraformResource = {
      address: 'aws_lambda_function.a',
      type: 'aws_lambda_function',
      name: 'a',
      values: {
        function_name: 'function-a',
        role: undefined,
      },
    } as unknown as TerraformResource;

    const functionB: TerraformResource = {
      address: 'aws_lambda_function.b',
      type: 'aws_lambda_function',
      name: 'b',
      values: {
        function_name: 'function-b',
        role: 'arn:aws:iam::123456789012:role/some-concrete-role',
      },
    } as unknown as TerraformResource;

    const factory = new Lambda012TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: functionA,
      allResources: [functionA, functionB],
    };

    const adapter = factory.bind(context);
    const result = lambda012Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when role is a non-string object (e.g., an unresolved expression) even if a sibling shares the literal text', () => {
    const functionA: TerraformResource = {
      address: 'aws_lambda_function.a',
      type: 'aws_lambda_function',
      name: 'a',
      values: {
        function_name: 'function-a',
        // Non-string -> unresolvable as far as the adapter is concerned.
        role: { unknown: true },
      },
    } as unknown as TerraformResource;

    const functionB: TerraformResource = {
      address: 'aws_lambda_function.b',
      type: 'aws_lambda_function',
      name: 'b',
      values: {
        function_name: 'function-b',
        role: 'arn:aws:iam::123456789012:role/some-concrete-role',
      },
    } as unknown as TerraformResource;

    const factory = new Lambda012TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: functionA,
      allResources: [functionA, functionB],
    };

    const adapter = factory.bind(context);
    const result = lambda012Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
