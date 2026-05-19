import { AdapterFactory, TfContext, IacRemediation } from '../../../../../src/assess/scanning/security-matrix/controls/types.js';
import { __Svc__Adapter } from './__safe-rule-id__.adapter.js';

export class Tf__Svc__AdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = ['__TF_TYPES__'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): Tf__Svc__Adapter {
    return new Tf__Svc__Adapter(context);
  }
}

class Tf__Svc__Adapter implements __Svc__Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  getRemediation(_scenario: string): IacRemediation | null {
    return null;
  }
}
