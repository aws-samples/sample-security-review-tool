import { describe, it, expect } from 'vitest';
import { lambda015Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.control.js';
import { Lambda015TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lambda015TfAdapterFactory();

function buildContext(resource: TerraformResource, allResources: TerraformResource[] = [resource]): TfContext {
  return {
    projectName: 'test-project',
    resource,
    allResources,
  };
}

describe('LAMBDA-015 (TF) - container image deployment with no image reference at all', () => {
  it('passes for aws_lambda_function configured as Image package_type but with no image_uri', () => {
    const resource: TerraformResource = {
      type: 'aws_lambda_function',
      name: 'container_fn',
      address: 'aws_lambda_function.container_fn',
      values: {
        function_name: 'my-container-fn',
        package_type: 'Image',
        role: 'arn:aws:iam::123456789012:role/lambda-role',
      },
    } as TerraformResource;

    const context = buildContext(resource);
    const adapter = factory.bind(context);
    const result = lambda015Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes for aws_lambda_function with Image package_type and image_uri explicitly null (unknown at plan time)', () => {
    const resource: TerraformResource = {
      type: 'aws_lambda_function',
      name: 'container_fn',
      address: 'aws_lambda_function.container_fn',
      values: {
        function_name: 'my-container-fn',
        package_type: 'Image',
        image_uri: null,
        role: 'arn:aws:iam::123456789012:role/lambda-role',
      },
    } as TerraformResource;

    const context = buildContext(resource);
    const adapter = factory.bind(context);
    const result = lambda015Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
