import { describe, it, expect } from 'vitest';
import { lambda015Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.control.js';
import { Lambda015TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const DIGEST = 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const IMAGE_URI_WITH_DIGEST = `123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app@${DIGEST}`;

function runControl(resource: TerraformResource) {
  const factory = new Lambda015TfAdapterFactory();
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  const adapter = factory.bind(context);
  return lambda015Control.run(adapter, context);
}

describe('LAMBDA-015 REQ-05 (TF): container image pinned by digest with no tag', () => {
  it('passes for aws_lambda_function whose image_uri pins by digest', () => {
    const resource: TerraformResource = {
      type: 'aws_lambda_function',
      name: 'my_fn',
      address: 'aws_lambda_function.my_fn',
      values: {
        package_type: 'Image',
        image_uri: IMAGE_URI_WITH_DIGEST,
      },
    } as TerraformResource;

    const result = runControl(resource);
    expect(result).toBeNull();
  });
});
