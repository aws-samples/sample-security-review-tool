import { describe, it, expect } from 'vitest';
import { lambda012Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.control.js';
import { Lambda012TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-012 REQ-05 (Terraform)', () => {
  it('passes when the execution role is an external ARN not referenced by any other in-scope Lambda', () => {
    const externalRoleArn = 'arn:aws:iam::123456789012:role/ExternalSharedRole';

    const functionA: TerraformResource = {
      address: 'aws_lambda_function.function_a',
      type: 'aws_lambda_function',
      name: 'function_a',
      values: {
        function_name: 'function-a',
        role: externalRoleArn,
        runtime: 'nodejs18.x',
        handler: 'index.handler',
      },
    } as any;

    const functionB: TerraformResource = {
      address: 'aws_lambda_function.function_b',
      type: 'aws_lambda_function',
      name: 'function_b',
      values: {
        function_name: 'function-b',
        // Different role — no in-scope sharing
        role: 'arn:aws:iam::123456789012:role/SomeOtherRole',
        runtime: 'nodejs18.x',
        handler: 'index.handler',
      },
    } as any;

    const allResources: TerraformResource[] = [functionA, functionB];

    const factory = new Lambda012TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: functionA,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = lambda012Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
