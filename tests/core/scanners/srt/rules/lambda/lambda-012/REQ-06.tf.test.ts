import { describe, it, expect } from 'vitest';
import { lambda012Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.control.js';
import { Lambda012TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-012 REQ-06 (Terraform): two Lambda functions share the same external execution role ARN', () => {
  it('flags both Lambda functions when they reference the same out-of-template role ARN', () => {
    const sharedRoleArn = 'arn:aws:iam::123456789012:role/external-shared-lambda-role';

    const lambdaA: TerraformResource = {
      address: 'aws_lambda_function.function_a',
      type: 'aws_lambda_function',
      name: 'function_a',
      values: {
        function_name: 'function-a',
        runtime: 'nodejs20.x',
        handler: 'index.handler',
        role: sharedRoleArn,
      },
    } as unknown as TerraformResource;

    const lambdaB: TerraformResource = {
      address: 'aws_lambda_function.function_b',
      type: 'aws_lambda_function',
      name: 'function_b',
      values: {
        function_name: 'function-b',
        runtime: 'nodejs20.x',
        handler: 'index.handler',
        role: sharedRoleArn,
      },
    } as unknown as TerraformResource;

    const allResources: TerraformResource[] = [lambdaA, lambdaB];
    const factory = new Lambda012TfAdapterFactory();

    const contextA: TfContext = {
      projectName: 'test-project',
      resource: lambdaA,
      allResources,
    };
    const contextB: TfContext = {
      projectName: 'test-project',
      resource: lambdaB,
      allResources,
    };

    const adapterA = factory.bind(contextA);
    const adapterB = factory.bind(contextB);

    const resultA = lambda012Control.run(adapterA, contextA);
    const resultB = lambda012Control.run(adapterB, contextB);

    expect(resultA).not.toBeNull();
    expect(resultA?.check_id).toBe('LAMBDA-012');
    expect(resultA?.resourceName).toBe('aws_lambda_function.function_a');
    expect(resultA?.resourceType).toBe('aws_lambda_function');
    expect(resultA?.status).toBe('Open');
    expect(resultA?.priority).toBe('HIGH');

    expect(resultB).not.toBeNull();
    expect(resultB?.check_id).toBe('LAMBDA-012');
    expect(resultB?.resourceName).toBe('aws_lambda_function.function_b');
    expect(resultB?.resourceType).toBe('aws_lambda_function');
    expect(resultB?.status).toBe('Open');
    expect(resultB?.priority).toBe('HIGH');
  });
});
