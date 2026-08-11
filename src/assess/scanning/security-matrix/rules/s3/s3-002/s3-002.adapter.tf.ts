import { AdapterFactory, TfContext } from '../../../controls/types.js';
import { PolicyStatement, S3002Adapter } from './s3-002.adapter.js';

export class S3002TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = ['aws_s3_bucket_policy', 'aws_s3_bucket'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): S3002TfAdapter {
    return new S3002TfAdapter(context);
  }
}

class S3002TfAdapter implements S3002Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  getPolicyStatements(): PolicyStatement[] {
    const values = (this.ctx.resource.values ?? {}) as Record<string, unknown>;
    const policy = values['policy'];
    return toPolicyStatements(policy);
  }
}

function toPolicyStatements(policy: unknown): PolicyStatement[] {
  const document = parsePolicyDocument(policy);
  if (!isObject(document)) return [];
  const raw = document['Statement'];
  const statements = Array.isArray(raw) ? raw : [raw];
  return statements.filter(isObject).map(toPolicyStatement);
}

function parsePolicyDocument(policy: unknown): unknown {
  if (typeof policy === 'string') {
    try {
      return JSON.parse(policy);
    } catch {
      return null;
    }
  }
  return policy;
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
