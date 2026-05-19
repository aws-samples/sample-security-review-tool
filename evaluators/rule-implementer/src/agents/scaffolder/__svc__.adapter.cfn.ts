import { AdapterFactory, CfnContext, IacRemediation } from '../../../../../src/assess/scanning/security-matrix/controls/types.js';
import { __Svc__Adapter } from './__svc__.adapter.js';

export class Cfn__Svc__AdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['__CFN_TYPES__'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): Cfn__Svc__Adapter {
    return new Cfn__Svc__Adapter(context);
  }
}

class Cfn__Svc__Adapter implements __Svc__Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  getRemediation(_scenario: string): IacRemediation | null {
    return null;
  }
}
