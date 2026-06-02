import { describe, it, expect } from 'vitest';
import { lambda015Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.control.js';
import { Lambda015TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

function buildContext(resource: TerraformResource, all: TerraformResource[] = [resource]): TfContext {
  return {
    projectName: 'test-project',
    resource,
    allResources: all,
  };
}

const factory = new Lambda015TfAdapterFactory();

describe('LAMBDA-015 REQ-07 (TF): tags containing "latest" substring but not exactly "latest" should pass', () => {
  const nonExactLatestTags = ['latest-stable', 'v1-latest', 'mylatest', 'latestish', 'LATEST-rc1', 'pre-Latest'];

  for (const tag of nonExactLatestTags) {
    it(`aws_lambda_function with tag '${tag}' does not flag`, () => {
      const resource: TerraformResource = {
        type: 'aws_lambda_function',
        name: 'my_fn',
        address: 'aws_lambda_function.my_fn',
        values: {
          package_type: 'Image',
          image_uri: `123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo:${tag}`,
        },
      } as TerraformResource;

      const ctx = buildContext(resource);
      const adapter = factory.bind(ctx);
      const result = lambda015Control.run(adapter, ctx);
      expect(result).toBeNull();
    });
  }
});
