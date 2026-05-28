import { AdapterFactory, CfnContext } from '../../../../../src/assess/scanning/security-matrix/controls/types.js';
import { __Rule__Adapter } from './__safe-rule-id__.adapter.js';

export class __Rule__CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['__CFN_TYPES__'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): __Rule__CfnAdapter {
    return new __Rule__CfnAdapter(context);
  }
}

class __Rule__CfnAdapter implements __Rule__Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }
}
