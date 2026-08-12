import { describe, expect, it } from 'vitest';
import { apigw003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.control.js';
import { Apigw003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.cfn.js';
import type {
  Apigw003Adapter,
} from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-003/apigw-003.adapter.js';
import type {
  CfnContext,
  ScanResult,
  Template,
} from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-13 (APIGW-003): A stage that belongs to a newer-generation API type (HTTP or
 * WebSocket API) cannot carry a stage-level WAF web ACL association at all, so it is
 * outside the rule's scope and must PASS even with no association present.
 *
 * The primary "must have a web ACL association" behaviour is owned by the base
 * requirement; it is asserted here only as the opposite case.
 */

const factory = new Apigw003CfnAdapterFactory();

function run(template: Template, logicalId: string): ScanResult | null {
  const resource = (template.Resources ?? {})[logicalId];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resource!,
    logicalId,
  };
  const adapter = factory.bind(context) as unknown as Apigw003Adapter;
  return apigw003Control.run(adapter, context);
}

// Values shown post-preprocessing: `!Ref TheApi` collapses to the logical ID string.
function templateWithApi(apiLogicalId: string, api: Record<string, unknown>): Template {
  return {
    Resources: {
      [apiLogicalId]: api,
      ApiStage: {
        Type: 'AWS::ApiGateway::Stage',
        Properties: {
          RestApiId: apiLogicalId,
          StageName: 'prod',
          DeploymentId: 'ApiDeployment',
        },
      },
    },
  } as unknown as Template;
}

describe('APIGW-003 REQ-13 (CloudFormation): newer-generation API stages are out of scope', () => {
  it('passes an HTTP API stage that has no web ACL association', () => {
    const template = templateWithApi('HttpApi', {
      Type: 'AWS::ApiGatewayV2::Api',
      Properties: { Name: 'http-api', ProtocolType: 'HTTP' },
    });

    expect(run(template, 'ApiStage')).toBeNull();
  });

  it('passes a WebSocket API stage that has no web ACL association', () => {
    const template = templateWithApi('SocketApi', {
      Type: 'AWS::ApiGatewayV2::Api',
      Properties: { Name: 'socket-api', ProtocolType: 'WEBSOCKET' },
    });

    expect(run(template, 'ApiStage')).toBeNull();
  });

  // Opposite outcome: identical shape, but the stage belongs to a REST API, where a
  // stage-level web ACL association IS supported and therefore required.
  it('flags an otherwise identical REST API stage with no web ACL association', () => {
    const template = templateWithApi('RestApi', {
      Type: 'AWS::ApiGateway::RestApi',
      Properties: { Name: 'rest-api' },
    });

    const result = run(template, 'ApiStage');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-003');
  });
});
