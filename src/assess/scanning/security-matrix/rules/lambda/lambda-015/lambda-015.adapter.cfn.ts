import { AdapterFactory, CfnContext } from '../../../controls/types.js';
import { Lambda015Adapter } from './lambda-015.adapter.js';

export class Lambda015CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::Lambda::Function', 'AWS::Serverless::Function'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): Lambda015CfnAdapter {
    return new Lambda015CfnAdapter(context);
  }
}

class Lambda015CfnAdapter implements Lambda015Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  getImageUri(): string | undefined {
    const properties = this.ctx.resource.Properties as Record<string, unknown> | undefined;
    if (!properties) return undefined;

    const rawImageUri = this.resourceType === 'AWS::Serverless::Function'
      ? properties['ImageUri']
      : this.extractCodeImageUri(properties);

    return this.resolveImageUri(rawImageUri);
  }

  private extractCodeImageUri(properties: Record<string, unknown>): unknown {
    const code = properties['Code'] as Record<string, unknown> | undefined;
    return code?.['ImageUri'];
  }

  private resolveImageUri(value: unknown): string | undefined {
    if (typeof value === 'string') return value;
    return this.findLatestTagInConditional(value);
  }

  private findLatestTagInConditional(value: unknown): string | undefined {
    if (!this.isPlainObject(value)) return undefined;

    const ifBranches = (value as Record<string, unknown>)['Fn::If'];
    if (!Array.isArray(ifBranches) || ifBranches.length !== 3) return undefined;

    const [, trueBranch, falseBranch] = ifBranches;
    return this.firstLatestTaggedBranch(trueBranch, falseBranch);
  }

  private firstLatestTaggedBranch(...branches: unknown[]): string | undefined {
    for (const branch of branches) {
      const resolved = this.resolveImageUri(branch);
      if (resolved && this.isLatestTagged(resolved)) return resolved;
    }
    return undefined;
  }

  private isLatestTagged(imageUri: string): boolean {
    const digestIndex = imageUri.indexOf('@');
    if (digestIndex !== -1) return false;

    const lastSlashIndex = imageUri.lastIndexOf('/');
    const lastSegment = lastSlashIndex === -1 ? imageUri : imageUri.slice(lastSlashIndex + 1);
    const colonIndex = lastSegment.indexOf(':');
    if (colonIndex === -1) return false;

    return lastSegment.slice(colonIndex + 1).toLowerCase() === 'latest';
  }

  private isPlainObject(value: unknown): boolean {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
  }
}
