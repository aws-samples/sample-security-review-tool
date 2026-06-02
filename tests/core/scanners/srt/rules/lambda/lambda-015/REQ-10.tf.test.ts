import { describe, it, expect } from 'vitest';
import { lambda015Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.control.js';
import { Lambda015TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-015 REQ-10 (Terraform): unresolvable image_uri', () => {
  it('passes when image_uri is null (unknown at plan time, e.g. sourced from a variable)', () => {
    // Plan reader records a value that is unknown at plan time as `null`.
    const resource: TerraformResource = {
      type: 'aws_lambda_function',
      name: 'my_fn',
      address: 'aws_lambda_function.my_fn',
      values: {
        package_type: 'Image',
        image_uri: null,
      },
    } as unknown as TerraformResource;

    const context: TfContext = {
      projectName: 'test-project',
      resource,
      allResources: [resource],
    };

    const factory = new Lambda015TfAdapterFactory();
    expect(factory.appliesTo('aws_lambda_function')).toBe(true);
    const adapter = factory.bind(context);

    const result = lambda015Control.run(adapter, context);
    expect(result).toBeNull();
  });

  it('passes when image_uri is absent entirely (multi-source interpolation collapsed away)', () => {
    // A multi-source interpolation that the plan reader cannot identify as a single
    // resource reference is omitted from `values` — the key is simply absent.
    const resource: TerraformResource = {
      type: 'aws_lambda_function',
      name: 'my_fn',
      address: 'aws_lambda_function.my_fn',
      values: {
        package_type: 'Image',
      },
    } as unknown as TerraformResource;

    const context: TfContext = {
      projectName: 'test-project',
      resource,
      allResources: [resource],
    };

    const factory = new Lambda015TfAdapterFactory();
    const adapter = factory.bind(context);

    const result = lambda015Control.run(adapter, context);
    expect(result).toBeNull();
  });
});
