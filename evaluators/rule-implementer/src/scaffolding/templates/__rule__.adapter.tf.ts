import { AdapterFactory, TfContext } from '../../../../../src/assess/scanning/security-matrix/controls/types.js';
import { __Rule__Adapter } from './__safe-rule-id__.adapter.js';

export class __Rule__TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = ['__TF_TYPES__'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): __Rule__TfAdapter {
    return new __Rule__TfAdapter(context);
  }
}

class __Rule__TfAdapter implements __Rule__Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }
}
