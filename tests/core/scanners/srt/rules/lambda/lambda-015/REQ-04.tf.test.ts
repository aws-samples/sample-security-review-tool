import { describe, it, expect } from 'vitest';
import { lambda015Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.control.js';
import { Lambda015TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const PROJECT_NAME = 'test-project';

function buildContext(resource: TerraformResource, allResources: TerraformResource[] = [resource]): TfContext {
  return { projectName: PROJECT_NAME, resource, allResources };
}

function runControl(resource: TerraformResource) {
  const factory = new Lambda015TfAdapterFactory();
  const ctx = buildContext(resource);
  const adapter = factory.bind(ctx);
  return lambda015Control.run(adapter, ctx);
}

describe('LAMBDA-015 REQ-04 (Terraform): Container image with specific non-latest tag passes', () => {
  it('passes when aws_lambda_function uses a semantic version tag', () => {
    const resource: TerraformResource = {
      type: 'aws_lambda_function',
      name: 'my_fn',
      address: 'aws_lambda_function.my_fn',
      values: {
        package_type: 'Image',
        image_uri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:1.2.3',
      },
    } as TerraformResource;

    const result = runControl(resource);
    expect(result).toBeNull();
  });

  it('passes when aws_lambda_function uses a build-number tag', () => {
    const resource: TerraformResource = {
      type: 'aws_lambda_function',
      name: 'build_fn',
      address: 'aws_lambda_function.build_fn',
      values: {
        package_type: 'Image',
        image_uri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:build-4567',
      },
    } as TerraformResource;

    const result = runControl(resource);
    expect(result).toBeNull();
  });

  it('passes when aws_lambda_function uses a commit SHA tag', () => {
    const resource: TerraformResource = {
      type: 'aws_lambda_function',
      name: 'sha_fn',
      address: 'aws_lambda_function.sha_fn',
      values: {
        package_type: 'Image',
        image_uri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:sha-a1b2c3d4e5f60718293a4b5c6d7e8f9012345678',
      },
    } as TerraformResource;

    const result = runControl(resource);
    expect(result).toBeNull();
  });

  it('passes when aws_lambda_function uses a v-prefixed semantic version tag', () => {
    const resource: TerraformResource = {
      type: 'aws_lambda_function',
      name: 'v_fn',
      address: 'aws_lambda_function.v_fn',
      values: {
        package_type: 'Image',
        image_uri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:v2.0.1',
      },
    } as TerraformResource;

    const result = runControl(resource);
    expect(result).toBeNull();
  });
});
