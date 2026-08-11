import { AdapterFactory, CfnContext } from '../../../controls/types.js';
import { PolicyStatement, S3002Adapter } from './s3-002.adapter.js';

export class S3002CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::S3::BucketPolicy', 'AWS::S3::Bucket'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): S3002CfnAdapter {
    return new S3002CfnAdapter(context);
  }
}

class S3002CfnAdapter implements S3002Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  getPolicyStatements(): PolicyStatement[] {
    const properties = (this.ctx.resource.Properties ?? {}) as Record<string, unknown>;
    const policyDocument = properties['PolicyDocument'];
    return toPolicyStatements(policyDocument);
  }
}

function toPolicyStatements(policyDocument: unknown): PolicyStatement[] {
  if (!isObject(policyDocument)) return [];
  const raw = policyDocument['Statement'];
  const statements = Array.isArray(raw) ? raw : [raw];
  return statements.filter(isObject).map(toPolicyStatement);
}

function toPolicyStatement(raw: Record<string, unknown>): PolicyStatement {
  return {
    effect: raw['Effect'],
    principal: raw['Principal'],
    condition: raw['Condition'],
  };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
