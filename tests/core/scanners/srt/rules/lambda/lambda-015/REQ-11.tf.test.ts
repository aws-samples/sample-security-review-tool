import { describe, it, expect } from 'vitest';
import { lambda015Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.control.js';
import { Lambda015TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-015 Terraform - REQ-11: unresolvable tag with known repository', () => {
  it('passes when image_uri is null because the tag portion is a multi-source interpolation the plan reader cannot collapse', () => {
    // The HCL would be something like:
    //   image_uri = "${data.aws_ecr_repository.app.repository_url}:${var.image_tag}"
    // Because the expression interpolates from more than one source (and the
    // tag side is not resolved at plan time), the plan reader leaves
    // image_uri as null. The adapter must treat null as "unknown" and pass.
    const lambdaResource: TerraformResource = {
      type: 'aws_lambda_function',
      name: 'app',
      address: 'aws_lambda_function.app',
      values: {
        function_name: 'app',
        package_type: 'Image',
        image_uri: null,
      },
    };

    const factory = new Lambda015TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: lambdaResource,
      allResources: [lambdaResource],
    };

    const adapter = factory.bind(context);
    const result = lambda015Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when image_uri is omitted entirely because its value is unknown at plan time', () => {
    // Plan reader behavior: a value unknown at plan time may be omitted from
    // values rather than recorded as null. Either form should pass.
    const lambdaResource: TerraformResource = {
      type: 'aws_lambda_function',
      name: 'app',
      address: 'aws_lambda_function.app',
      values: {
        function_name: 'app',
        package_type: 'Image',
        // image_uri intentionally absent
      },
    };

    const factory = new Lambda015TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: lambdaResource,
      allResources: [lambdaResource],
    };

    const adapter = factory.bind(context);
    const result = lambda015Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
