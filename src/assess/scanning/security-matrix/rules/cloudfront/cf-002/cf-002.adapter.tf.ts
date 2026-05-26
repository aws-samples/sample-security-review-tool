import { AdapterFactory, TfContext } from '../../../controls/types.js';
import { Cf002Adapter } from './cf-002.adapter.js';

export class Cf002TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = ['aws_cloudfront_distribution'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): Cf002TfAdapter {
    return new Cf002TfAdapter(context);
  }
}

class Cf002TfAdapter implements Cf002Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  hasWebAclAssociation(): boolean {
    const webAclId = this.ctx.resource.values?.web_acl_id;
    return this.isNonEmptyValue(webAclId);
  }

  private isNonEmptyValue(value: unknown): boolean {
    if (value === undefined || value === null) return false;
    if (typeof value === 'string') return value.length > 0;
    return true;
  }
}
