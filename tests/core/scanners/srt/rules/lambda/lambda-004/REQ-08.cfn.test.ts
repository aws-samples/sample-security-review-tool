import { describe, it, expect } from 'vitest';
import { lambda004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.control.js';
import { Lambda004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.adapter.cfn.js';
import { CfnContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-08 (CloudFormation): Lambda function has no tracing configuration regardless of
 * the event source type or runtime/package format used.
 *
 * Per resolved decision, the rule applies uniformly to all Lambda functions regardless
 * of whether their event sources support X-Ray tracing (e.g. MSK, self-managed Kafka,
 * Amazon MQ, DocumentDB) or their packaging format (Zip vs Image). The rule must flag
 * the resource whenever no tracing configuration is present.
 */
describe('LAMBDA-004 REQ-08 [CFN]: missing tracing configuration is flagged regardless of event source / runtime / package format', () => {
  const factory = new Lambda004CfnAdapterFactory();

  function buildContext(logicalId: string, resource: any): CfnContext {
    return {
      stackName: 'test-stack',
      template: { Resources: { [logicalId]: resource } } as any,
      resource,
      logicalId,
    };
  }

  it('flags AWS::Lambda::Function (Zip package) with no TracingConfig', () => {
    const resource = {
      Type: 'AWS::Lambda::Function',
      Properties: {
        FunctionName: 'fn-zip-no-tracing',
        Runtime: 'nodejs20.x',
        Handler: 'index.handler',
        Role: 'arn:aws:iam::123456789012:role/lambda-role',
        PackageType: 'Zip',
        Code: { S3Bucket: 'b', S3Key: 'k' },
        // No TracingConfig at all
      },
    };
    const ctx = buildContext('FnZipNoTracing', resource);
    const adapter = factory.bind(ctx);

    const result = lambda004Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LAMBDA-004');
    expect(result!.resourceType).toBe('AWS::Lambda::Function');
    expect(result!.resourceName).toBe('FnZipNoTracing');
    expect(result!.status).toBe('Open');
  });

  it('flags AWS::Lambda::Function (Image package) with no TracingConfig', () => {
    const resource = {
      Type: 'AWS::Lambda::Function',
      Properties: {
        FunctionName: 'fn-image-no-tracing',
        PackageType: 'Image',
        Role: 'arn:aws:iam::123456789012:role/lambda-role',
        Code: { ImageUri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/repo:tag' },
        // No TracingConfig at all
      },
    };
    const ctx = buildContext('FnImageNoTracing', resource);
    const adapter = factory.bind(ctx);

    const result = lambda004Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LAMBDA-004');
    expect(result!.resourceType).toBe('AWS::Lambda::Function');
  });

  it('flags AWS::Lambda::Function with no tracing even when wired to MSK event source mapping', () => {
    // MSK event sources do not propagate X-Ray context, but the rule still applies uniformly.
    const resource = {
      Type: 'AWS::Lambda::Function',
      Properties: {
        FunctionName: 'fn-msk-consumer',
        Runtime: 'python3.12',
        Handler: 'app.handler',
        Role: 'arn:aws:iam::123456789012:role/lambda-role',
        Code: { S3Bucket: 'b', S3Key: 'k' },
        // No TracingConfig at all — even though event source is MSK
      },
    };
    const ctx = buildContext('FnMskConsumer', resource);
    const adapter = factory.bind(ctx);

    const result = lambda004Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LAMBDA-004');
  });

  it('flags AWS::Lambda::Function with no tracing for self-managed Kafka / Amazon MQ / DocumentDB event sources', () => {
    // Same behavior expected for all event source types whose service does not propagate trace context.
    const resource = {
      Type: 'AWS::Lambda::Function',
      Properties: {
        FunctionName: 'fn-mq-docdb-consumer',
        Runtime: 'java17',
        Handler: 'com.example.Handler::handle',
        Role: 'arn:aws:iam::123456789012:role/lambda-role',
        Code: { S3Bucket: 'b', S3Key: 'k' },
        // No TracingConfig
      },
    };
    const ctx = buildContext('FnMqDocDbConsumer', resource);
    const adapter = factory.bind(ctx);

    const result = lambda004Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LAMBDA-004');
  });

  it('flags AWS::Serverless::Function with no Tracing property', () => {
    const resource = {
      Type: 'AWS::Serverless::Function',
      Properties: {
        FunctionName: 'sam-fn-no-tracing',
        Runtime: 'nodejs20.x',
        Handler: 'index.handler',
        CodeUri: 's3://b/k',
        // No Tracing property at all
      },
    };
    const ctx = buildContext('SamFnNoTracing', resource);
    const adapter = factory.bind(ctx);

    const result = lambda004Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LAMBDA-004');
    expect(result!.resourceType).toBe('AWS::Serverless::Function');
  });

  it('flags AWS::Serverless::Function (Image package) with no Tracing property', () => {
    const resource = {
      Type: 'AWS::Serverless::Function',
      Properties: {
        FunctionName: 'sam-fn-image-no-tracing',
        PackageType: 'Image',
        ImageUri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/repo:tag',
        // No Tracing property at all
      },
    };
    const ctx = buildContext('SamFnImageNoTracing', resource);
    const adapter = factory.bind(ctx);

    const result = lambda004Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LAMBDA-004');
    expect(result!.resourceType).toBe('AWS::Serverless::Function');
  });

  it('flags AWS::Lambda::Function when Properties is entirely absent (no tracing config possible)', () => {
    const resource = {
      Type: 'AWS::Lambda::Function',
      // No Properties at all
    };
    const ctx = buildContext('FnNoProps', resource);
    const adapter = factory.bind(ctx);

    const result = lambda004Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LAMBDA-004');
  });
});
