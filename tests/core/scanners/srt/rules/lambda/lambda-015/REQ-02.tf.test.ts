import { describe, it, expect } from 'vitest';
import { lambda015Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.control.js';
import { Lambda015TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

function buildContext(resource: TerraformResource): TfContext {
  return {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
}

describe('LAMBDA-015 REQ-02 (Terraform): case-insensitive match of "latest" must flag', () => {
  const factory = new Lambda015TfAdapterFactory();

  it('flags aws_lambda_function whose image_uri tag is "Latest" (mixed case)', () => {
    const resource: TerraformResource = {
      type: 'aws_lambda_function',
      name: 'my_fn',
      address: 'aws_lambda_function.my_fn',
      values: {
        package_type: 'Image',
        image_uri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:Latest',
      },
    } as TerraformResource;

    const ctx = buildContext(resource);
    const adapter = factory.bind(ctx);
    const result = lambda015Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-015');
    expect(result?.resourceName).toBe('aws_lambda_function.my_fn');
  });

  it('flags aws_lambda_function whose image_uri tag is "LATEST" (all caps)', () => {
    const resource: TerraformResource = {
      type: 'aws_lambda_function',
      name: 'my_fn',
      address: 'aws_lambda_function.my_fn',
      values: {
        package_type: 'Image',
        image_uri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:LATEST',
      },
    } as TerraformResource;

    const ctx = buildContext(resource);
    const adapter = factory.bind(ctx);
    const result = lambda015Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-015');
  });

  it('flags aws_lambda_function whose image_uri tag is "LaTeSt" (alternating case)', () => {
    const resource: TerraformResource = {
      type: 'aws_lambda_function',
      name: 'my_fn',
      address: 'aws_lambda_function.my_fn',
      values: {
        package_type: 'Image',
        image_uri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:LaTeSt',
      },
    } as TerraformResource;

    const ctx = buildContext(resource);
    const adapter = factory.bind(ctx);
    const result = lambda015Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-015');
  });
});
