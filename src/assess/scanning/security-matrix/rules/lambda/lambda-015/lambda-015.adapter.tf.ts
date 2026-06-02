import { AdapterFactory, TfContext } from '../../../controls/types.js';
import { Lambda015Adapter } from './lambda-015.adapter.js';

export class Lambda015TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = ['aws_lambda_function'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): Lambda015TfAdapter {
    return new Lambda015TfAdapter(context);
  }
}

class Lambda015TfAdapter implements Lambda015Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  getImageUri(): string | undefined {
    const values = this.ctx.resource.values as Record<string, unknown> | undefined;
    const imageUri = values?.['image_uri'];
    return typeof imageUri === 'string' ? imageUri : undefined;
  }
}
