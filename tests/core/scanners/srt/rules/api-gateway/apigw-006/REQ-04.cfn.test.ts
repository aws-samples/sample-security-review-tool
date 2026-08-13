import { describe, expect, it } from 'vitest';
import { apigw006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.control.js';
import { Apigw006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.cfn.js';
import type { Apigw006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw006CfnAdapterFactory();

function buildContext(loggingLevel: string): CfnContext {
  const resource = {
    Type: 'AWS::ApiGateway::Stage',
    Properties: {
      RestApiId: 'MyRestApi',
      DeploymentId: 'MyDeployment',
      StageName: 'prod',
      // Catch-all method setting: applies to every method and every path
      MethodSettings: [
        {
          ResourcePath: '/*',
          HttpMethod: '*',
          LoggingLevel: loggingLevel,
        },
      ],
    },
  } as unknown as Resource;

  const template = { Resources: { MyStage: resource } } as unknown as Template;

  return { stackName: 'test-stack', template, resource, logicalId: 'MyStage' };
}

function run(loggingLevel: string) {
  const context = buildContext(loggingLevel);
  const adapter = factory.bind(context) as Apigw006Adapter;
  return apigw006Control.run(adapter, context);
}

describe('APIGW-006 (CloudFormation) - catch-all method setting with logging level off', () => {
  // Primary behavior owned by this requirement: a catch-all method setting whose
  // logging level is explicitly OFF means no execution logs reach CloudWatch Logs.
  it('flags a stage whose catch-all method setting sets LoggingLevel to OFF', () => {
    const result = run('OFF');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
    expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
    expect(result?.resourceName).toBe('MyStage');
  });

  it('flags a stage whose catch-all method setting sets LoggingLevel to lowercase off', () => {
    const result = run('off');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
  });

  // Opposite outcome: nearest input that flips the verdict - same catch-all
  // setting, but with an accepted logging level in effect.
  it('does not flag an otherwise identical catch-all method setting with LoggingLevel INFO', () => {
    expect(run('INFO')).toBeNull();
  });
});
