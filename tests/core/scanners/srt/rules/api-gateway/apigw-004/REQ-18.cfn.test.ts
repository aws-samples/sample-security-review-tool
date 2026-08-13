import { describe, it, expect } from 'vitest';
import { apigw004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.control.js';
import { Apigw004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/apigw-004/apigw-004.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Apigw004CfnAdapterFactory();

function api(protocolType: string): Resource {
  return {
    Type: 'AWS::ApiGatewayV2::Api',
    Properties: { Name: 'orders', ProtocolType: protocolType, RouteSelectionExpression: '$request.body.action' },
  } as unknown as Resource;
}

// Ref to a logical id resolves to the logical id string after preprocessing.
function route(routeKey: string, properties: Record<string, unknown> = {}): Resource {
  return {
    Type: 'AWS::ApiGatewayV2::Route',
    Properties: { ApiId: 'Api', RouteKey: routeKey, ...properties },
  } as unknown as Resource;
}

function scan(protocolType: string, routeKey: string, properties?: Record<string, unknown>) {
  const resource = route(routeKey, properties);
  const template = { Resources: { Api: api(protocolType), Route: resource } } as unknown as Template;
  const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId: 'Route' };
  return apigw004Control.run(factory.bind(context), context);
}

describe('APIGW-004 REQ-18 (CloudFormation): WebSocket routes other than $connect cannot carry authorization', () => {
  it('passes a $disconnect route that declares AuthorizationType NONE', () => {
    expect(scan('WEBSOCKET', '$disconnect', { AuthorizationType: 'NONE' })).toBeNull();
  });

  it('passes a $default route with no authorization configured at all', () => {
    expect(scan('WEBSOCKET', '$default')).toBeNull();
  });

  it('passes a custom route that declares AuthorizationType NONE', () => {
    expect(scan('WEBSOCKET', 'sendmessage', { AuthorizationType: 'NONE' })).toBeNull();
  });

  // Opposite outcome: $connect is the one WebSocket route that does take an
  // authorizer, so the exclusion must not reach it.
  it('flags a $connect route that declares AuthorizationType NONE', () => {
    const result = scan('WEBSOCKET', '$connect', { AuthorizationType: 'NONE' });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
  });

  // Opposite outcome: the nearest input that flips the verdict - the same
  // unauthenticated $default route on an HTTP API, where any route takes an
  // authorizer.
  it('flags a $default route on an HTTP API', () => {
    const result = scan('HTTP', '$default', { AuthorizationType: 'NONE' });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('APIGW-004');
  });

  it('flags a WebSocket route when the API it belongs to is not in the template', () => {
    const resource = route('$default', { ApiId: 'ApiInAnotherStack', AuthorizationType: 'NONE' });
    const template = { Resources: { Route: resource } } as unknown as Template;
    const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId: 'Route' };

    const result = apigw004Control.run(factory.bind(context), context);

    expect(result).not.toBeNull();
  });
});
