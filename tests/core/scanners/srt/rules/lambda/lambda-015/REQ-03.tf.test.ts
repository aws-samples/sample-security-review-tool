import { describe, it, expect } from 'vitest';
import { lambda015Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.control.js';
import { Lambda015TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-03 (Terraform): Lambda function uses a container image reference that
 * includes a repository but no tag and no digest. The OCI/Docker convention is
 * to default to 'latest' at pull time, so the rule must flag this as an
 * implicit 'latest' reference.
 */
describe('LAMBDA-015 REQ-03 (Terraform): untagged image reference is flagged as implicit latest', () => {
  const factory = new Lambda015TfAdapterFactory();

  function runControl(resource: TerraformResource) {
    const context: TfContext = {
      projectName: 'test-project',
      resource,
      allResources: [resource],
    };
    const adapter = factory.bind(context);
    return lambda015Control.run(adapter, context);
  }

  it('flags aws_lambda_function when image_uri references a repository with no tag and no digest (literal form)', () => {
    const resource: TerraformResource = {
      type: 'aws_lambda_function',
      name: 'my_fn',
      address: 'aws_lambda_function.my_fn',
      values: {
        package_type: 'Image',
        image_uri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo',
      },
    } as TerraformResource;

    const result = runControl(resource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-015');
  });

  it('flags aws_lambda_function with a simple repository name and no tag', () => {
    const resource: TerraformResource = {
      type: 'aws_lambda_function',
      name: 'my_fn',
      address: 'aws_lambda_function.my_fn',
      values: {
        package_type: 'Image',
        image_uri: 'my-repo',
      },
    } as TerraformResource;

    const result = runControl(resource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-015');
  });
});
