import { describe, it, expect } from 'vitest';
import { lambda015Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.control.js';
import { Lambda015TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-015 REQ-08 [TF] - Zip-package Lambda functions are out of scope', () => {
  const factory = new Lambda015TfAdapterFactory();

  it('passes for aws_lambda_function deployed as a zip archive (no image_uri)', () => {
    const resource: TerraformResource = {
      type: 'aws_lambda_function',
      name: 'zip_function',
      address: 'aws_lambda_function.zip_function',
      values: {
        function_name: 'my-zip-function',
        runtime: 'nodejs20.x',
        handler: 'index.handler',
        role: 'arn:aws:iam::123456789012:role/lambda-role',
        package_type: 'Zip',
        filename: 'code.zip',
      },
    } as TerraformResource;

    const context: TfContext = {
      projectName: 'test-project',
      resource,
      allResources: [resource],
    };

    const adapter = factory.bind(context);
    const result = lambda015Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes for aws_lambda_function with s3-based zip deployment (no image_uri)', () => {
    const resource: TerraformResource = {
      type: 'aws_lambda_function',
      name: 's3_zip_function',
      address: 'aws_lambda_function.s3_zip_function',
      values: {
        function_name: 'my-s3-zip-function',
        runtime: 'python3.11',
        handler: 'app.handler',
        role: 'arn:aws:iam::123456789012:role/lambda-role',
        package_type: 'Zip',
        s3_bucket: 'my-deployment-bucket',
        s3_key: 'lambda/code.zip',
      },
    } as TerraformResource;

    const context: TfContext = {
      projectName: 'test-project',
      resource,
      allResources: [resource],
    };

    const adapter = factory.bind(context);
    const result = lambda015Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
