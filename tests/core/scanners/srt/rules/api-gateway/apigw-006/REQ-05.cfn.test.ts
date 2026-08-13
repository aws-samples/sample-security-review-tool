import { describe, expect, it } from 'vitest';
import { apigw006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.control.js';
import { Apigw006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-006/apigw-006.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw006CfnAdapterFactory();

function stageWithCatchAllLoggingLevel(loggingLevel: string): Resource {
  return {
    Type: 'AWS::ApiGateway::Stage',
    Properties: {
      RestApiId: 'MyRestApi',
      DeploymentId: 'MyDeployment',
      StageName: 'prod',
      MethodSettings: [
        {
          HttpMethod: '*',
          ResourcePath: '/*',
          LoggingLevel: loggingLevel,
        },
      ],
    },
  } as unknown as Resource;
}

function contextFor(resource: Resource): CfnContext {
  const template = { Resources: { ApiStage: resource } } as unknown as Template;
  return { stackName: 'test-stack', template, resource, logicalId: 'ApiStage' };
}

function run(resource: Resource) {
  const context = contextFor(resource);
  const adapter = factory.bind(context);
  return apigw006Control.run(adapter, context);
}

describe('APIGW-006 (CloudFormation) — catch-all method setting logging level must be INFO or ERROR', () => {
  // Primary behavior owned by this requirement: an unrecognized logging level must be flagged.
  it('flags a stage whose catch-all method setting uses an unrecognized logging level', () => {
    const result = run(stageWithCatchAllLoggingLevel('VERBOSE'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
    expect(result?.resourceType).toBe('AWS::ApiGateway::Stage');
    expect(result?.resourceName).toBe('ApiStage');
  });

  it('flags a stage whose catch-all method setting uses a logging level of OFF', () => {
    const result = run(stageWithCatchAllLoggingLevel('OFF'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-006');
  });

  // Opposite outcome: same catch-all setting, but with an accepted level present.
  it('does not flag a stage whose catch-all method setting uses the accepted INFO logging level', () => {
    expect(run(stageWithCatchAllLoggingLevel('INFO'))).toBeNull();
  });
});
