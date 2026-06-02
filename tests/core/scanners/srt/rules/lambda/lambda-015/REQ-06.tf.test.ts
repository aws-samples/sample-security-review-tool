import { describe, it, expect } from 'vitest';
import { lambda015Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.control.js';
import { Lambda015TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const IMAGE_URI_WITH_LATEST_AND_DIGEST =
  '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo:latest@sha256:abc123def4567890abc123def4567890abc123def4567890abc123def4567890';

function runControl(resource: TerraformResource, allResources: TerraformResource[]) {
  const factory = new Lambda015TfAdapterFactory();
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources,
  };
  const adapter = factory.bind(context);
  return lambda015Control.run(adapter, context);
}

describe('LAMBDA-015 REQ-06 (Terraform): image URI with both latest tag and digest', () => {
  it('passes for aws_lambda_function when image_uri contains latest tag and digest', () => {
    const resource: TerraformResource = {
      type: 'aws_lambda_function',
      name: 'my_function',
      address: 'aws_lambda_function.my_function',
      values: {
        package_type: 'Image',
        image_uri: IMAGE_URI_WITH_LATEST_AND_DIGEST,
        function_name: 'my-function',
      },
    };

    const result = runControl(resource, [resource]);
    expect(result).toBeNull();
  });
});
