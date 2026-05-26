import { AdapterFactory, CfnContext } from '../../../controls/types.js';
import { Cf002Adapter } from './cf-002.adapter.js';

export class Cf002CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::CloudFront::Distribution'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): Cf002CfnAdapter {
    return new Cf002CfnAdapter(context);
  }
}

class Cf002CfnAdapter implements Cf002Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  hasWebAclAssociation(): boolean {
    const distributionConfig = this.ctx.resource.Properties?.DistributionConfig;
    const webAclId = distributionConfig?.WebACLId;
    return this.isNonEmptyValue(webAclId);
  }

  private isNonEmptyValue(value: unknown): boolean {
    if (value === undefined || value === null) return false;
    if (typeof value === 'string') return value.length > 0;
    return true;
  }
}
