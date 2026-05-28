import { describe, it, expect } from 'vitest';
import { lambda012Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.control.js';
import { Lambda012CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.adapter.cfn.js';
import { CfnContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-09 (CloudFormation):
 * A template contains exactly one Lambda function that references an execution role,
 * and the same role is also referenced by a non-Lambda resource (e.g., used as an
 * instance profile by an EC2 instance, or assumed by a different service via a
 * multi-principal trust policy).
 *
 * Expected behavior: flag
 * Rationale: any cross-resource sharing of a Lambda execution role violates the rule.
 */
describe('LAMBDA-012 REQ-09 (CloudFormation): Lambda execution role shared with a non-Lambda resource', () => {
  it('flags the Lambda function when its execution role is also used by a non-Lambda resource (EC2 instance profile)', () => {
    const template = {
      Resources: {
        SharedRole: {
          Type: 'AWS::IAM::Role',
          Properties: {
            AssumeRolePolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    Service: ['lambda.amazonaws.com', 'ec2.amazonaws.com'],
                  },
                  Action: 'sts:AssumeRole',
                },
              ],
            },
          },
        },
        SharedInstanceProfile: {
          Type: 'AWS::IAM::InstanceProfile',
          Properties: {
            // After preprocessing !Ref SharedRole resolves to "SharedRole"
            Roles: ['SharedRole'],
          },
        },
        AppInstance: {
          Type: 'AWS::EC2::Instance',
          Properties: {
            ImageId: 'ami-12345678',
            InstanceType: 't3.micro',
            // After preprocessing !Ref SharedInstanceProfile resolves to "SharedInstanceProfile"
            IamInstanceProfile: 'SharedInstanceProfile',
          },
        },
        AppFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'app-function',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            Code: { ZipFile: 'exports.handler = async () => {};' },
            // After preprocessing !GetAtt SharedRole.Arn resolves to "SharedRole"
            Role: 'SharedRole',
          },
        },
      },
    } as const;

    const factory = new Lambda012CfnAdapterFactory();
    const lambdaResource = template.Resources.AppFunction;

    expect(factory.appliesTo(lambdaResource.Type)).toBe(true);

    const context: CfnContext = {
      stackName: 'test-stack',
      template: template as unknown as CfnContext['template'],
      resource: lambdaResource as unknown as CfnContext['resource'],
      logicalId: 'AppFunction',
    };

    const adapter = factory.bind(context);
    const result = lambda012Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-012');
    expect(result?.resourceName).toBe('AppFunction');
    expect(result?.resourceType).toBe('AWS::Lambda::Function');
    expect(result?.status).toBe('Open');
    expect(result?.priority).toBe('HIGH');
  });

  it('flags a Serverless::Function when its execution role is also assumed by a non-Lambda service principal (multi-principal trust policy)', () => {
    const template = {
      Resources: {
        MultiPrincipalRole: {
          Type: 'AWS::IAM::Role',
          Properties: {
            AssumeRolePolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    Service: ['lambda.amazonaws.com', 'ecs-tasks.amazonaws.com'],
                  },
                  Action: 'sts:AssumeRole',
                },
              ],
            },
          },
        },
        EcsTaskDefinition: {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            Family: 'app',
            // Non-Lambda resource referencing the same role
            TaskRoleArn: 'MultiPrincipalRole',
            ExecutionRoleArn: 'MultiPrincipalRole',
            ContainerDefinitions: [
              { Name: 'app', Image: 'nginx', Memory: 256 },
            ],
          },
        },
        ServerlessApi: {
          Type: 'AWS::Serverless::Function',
          Properties: {
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            CodeUri: 's3://bucket/key',
            Role: 'MultiPrincipalRole',
          },
        },
      },
    } as const;

    const factory = new Lambda012CfnAdapterFactory();
    const lambdaResource = template.Resources.ServerlessApi;

    expect(factory.appliesTo(lambdaResource.Type)).toBe(true);

    const context: CfnContext = {
      stackName: 'test-stack',
      template: template as unknown as CfnContext['template'],
      resource: lambdaResource as unknown as CfnContext['resource'],
      logicalId: 'ServerlessApi',
    };

    const adapter = factory.bind(context);
    const result = lambda012Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-012');
    expect(result?.resourceName).toBe('ServerlessApi');
    expect(result?.resourceType).toBe('AWS::Serverless::Function');
  });
});
