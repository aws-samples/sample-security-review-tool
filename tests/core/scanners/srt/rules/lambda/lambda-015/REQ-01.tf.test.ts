import { describe, it, expect } from 'vitest';
import { lambda015Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.control.js';
import { Lambda015TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-015 REQ-01 (Terraform): container image using latest tag', () => {
  it('flags aws_lambda_function whose image_uri (literal) uses the lowercase :latest tag', () => {
    const fn: TerraformResource = {
      type: 'aws_lambda_function',
      name: 'container_fn',
      address: 'aws_lambda_function.container_fn',
      values: {
        function_name: 'my-container-fn',
        package_type: 'Image',
        image_uri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:latest',
        role: 'arn:aws:iam::123456789012:role/lambda-role',
      },
    } as TerraformResource;

    const factory = new Lambda015TfAdapterFactory();
    expect(factory.appliesTo(fn.type)).toBe(true);

    const context: TfContext = {
      projectName: 'test-project',
      resource: fn,
      allResources: [fn],
    };

    const adapter = factory.bind(context);
    const result = lambda015Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-015');
    expect(result?.resourceType).toBe('aws_lambda_function');
    expect(result?.resourceName).toBe('aws_lambda_function.container_fn');
    expect(result?.status).toBe('Open');
  });
});
