import { describe, it, expect } from 'vitest';
import { lambda012Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.control.js';
import { Lambda012TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-09 (Terraform):
 * A plan contains exactly one aws_lambda_function that references an execution role,
 * and the same role is also referenced by a non-Lambda resource (for example used as
 * an EC2 instance profile, or assumed by a different service via a multi-principal
 * trust policy).
 *
 * Expected behavior: flag
 * Rationale: any cross-resource sharing of a Lambda execution role violates the rule.
 */
describe('LAMBDA-012 REQ-09 (Terraform): Lambda execution role shared with a non-Lambda resource', () => {
  it('flags the aws_lambda_function when its execution role is also used by an EC2 instance profile', () => {
    const sharedRoleArn = 'arn:aws:iam::123456789012:role/shared-role';

    const lambdaResource: TerraformResource = {
      address: 'aws_lambda_function.app',
      type: 'aws_lambda_function',
      name: 'app',
      values: {
        function_name: 'app-function',
        runtime: 'nodejs20.x',
        handler: 'index.handler',
        role: sharedRoleArn,
      },
    } as unknown as TerraformResource;

    const instanceProfile: TerraformResource = {
      address: 'aws_iam_instance_profile.shared',
      type: 'aws_iam_instance_profile',
      name: 'shared',
      values: {
        name: 'shared-instance-profile',
        role: sharedRoleArn,
      },
    } as unknown as TerraformResource;

    const ec2Instance: TerraformResource = {
      address: 'aws_instance.app',
      type: 'aws_instance',
      name: 'app',
      values: {
        ami: 'ami-12345678',
        instance_type: 't3.micro',
        iam_instance_profile: 'shared-instance-profile',
      },
    } as unknown as TerraformResource;

    const allResources: TerraformResource[] = [lambdaResource, instanceProfile, ec2Instance];

    const factory = new Lambda012TfAdapterFactory();
    expect(factory.appliesTo(lambdaResource.type)).toBe(true);

    const context: TfContext = {
      projectName: 'test-project',
      resource: lambdaResource,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = lambda012Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-012');
    expect(result?.resourceName).toBe('aws_lambda_function.app');
    expect(result?.resourceType).toBe('aws_lambda_function');
    expect(result?.status).toBe('Open');
    expect(result?.priority).toBe('HIGH');
  });

  it('flags the aws_lambda_function when its execution role is also assumed by another service (ECS task role)', () => {
    const sharedRoleArn = 'arn:aws:iam::123456789012:role/multi-principal-role';

    const lambdaResource: TerraformResource = {
      address: 'aws_lambda_function.api',
      type: 'aws_lambda_function',
      name: 'api',
      values: {
        function_name: 'api-function',
        runtime: 'nodejs20.x',
        handler: 'index.handler',
        role: sharedRoleArn,
      },
    } as unknown as TerraformResource;

    const ecsTaskDefinition: TerraformResource = {
      address: 'aws_ecs_task_definition.app',
      type: 'aws_ecs_task_definition',
      name: 'app',
      values: {
        family: 'app',
        task_role_arn: sharedRoleArn,
        execution_role_arn: sharedRoleArn,
      },
    } as unknown as TerraformResource;

    const allResources: TerraformResource[] = [lambdaResource, ecsTaskDefinition];

    const factory = new Lambda012TfAdapterFactory();
    expect(factory.appliesTo(lambdaResource.type)).toBe(true);

    const context: TfContext = {
      projectName: 'test-project',
      resource: lambdaResource,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = lambda012Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-012');
    expect(result?.resourceName).toBe('aws_lambda_function.api');
    expect(result?.resourceType).toBe('aws_lambda_function');
  });
});
