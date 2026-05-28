import { AdapterFactory, TfContext } from '../../../controls/types.js';
import {
  Cf006Adapter,
  UnprotectedOacEligibleOrigin,
  UnprotectedS3Origin,
  isMissing,
  isOacEligibleNonS3Domain,
  isS3OriginDomain,
} from './cf-006.adapter.js';

const OAC_RESOURCE_TYPE = 'aws_cloudfront_origin_access_control';

export class Cf006TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = ['aws_cloudfront_distribution'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): Cf006TfAdapter {
    return new Cf006TfAdapter(context);
  }
}

class Cf006TfAdapter implements Cf006Adapter {
  readonly resourceId: string;
  readonly resourceType: string;
  readonly unprotectedS3Origins: UnprotectedS3Origin[];
  readonly unprotectedOacEligibleOrigins: UnprotectedOacEligibleOrigin[];

  constructor(ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
    const origins = this.getOrigins(ctx);
    const oacIdentifiers = this.collectOacIdentifiers(ctx);
    this.unprotectedS3Origins = this.findUnprotectedS3Origins(origins, oacIdentifiers);
    this.unprotectedOacEligibleOrigins = this.findUnprotectedOacEligibleOrigins(origins, oacIdentifiers);
  }

  private findUnprotectedS3Origins(origins: any[], oacIdentifiers: Set<string>): UnprotectedS3Origin[] {
    return origins
      .filter(origin => this.isUnprotectedS3Origin(origin, oacIdentifiers))
      .map(origin => ({ originId: String(origin?.origin_id ?? '') }));
  }

  private findUnprotectedOacEligibleOrigins(origins: any[], oacIdentifiers: Set<string>): UnprotectedOacEligibleOrigin[] {
    return origins
      .filter(origin => this.isUnprotectedNonS3OacEligibleOrigin(origin, oacIdentifiers))
      .map(origin => ({ originId: String(origin?.origin_id ?? '') }));
  }

  private getOrigins(ctx: TfContext): any[] {
    const origins = (ctx.resource as any).values?.origin;
    return Array.isArray(origins) ? origins : [];
  }

  private collectOacIdentifiers(ctx: TfContext): Set<string> {
    const identifiers = new Set<string>();
    for (const resource of ctx.allResources) {
      if (resource.type !== OAC_RESOURCE_TYPE) continue;
      const id = (resource as any).values?.id;
      if (typeof id === 'string' && id !== '') identifiers.add(id);
    }
    return identifiers;
  }

  private isUnprotectedS3Origin(origin: any, oacIdentifiers: Set<string>): boolean {
    if (!origin || typeof origin !== 'object') return false;
    const s3Config = this.firstOrSelf(origin.s3_origin_config);
    if (!this.isS3Origin(origin, s3Config)) return false;
    if (!isMissing(s3Config?.origin_access_identity)) return false;
    return !this.hasResolvedOacReference(origin.origin_access_control_id, oacIdentifiers);
  }

  private isUnprotectedNonS3OacEligibleOrigin(origin: any, oacIdentifiers: Set<string>): boolean {
    if (!origin || typeof origin !== 'object') return false;
    const s3Config = this.firstOrSelf(origin.s3_origin_config);
    if (this.isS3Origin(origin, s3Config)) return false;
    if (!isOacEligibleNonS3Domain(origin.domain_name)) return false;
    return !this.hasResolvedOacReference(origin.origin_access_control_id, oacIdentifiers);
  }

  private hasResolvedOacReference(value: unknown, oacIdentifiers: Set<string>): boolean {
    if (isMissing(value)) return false;
    if (typeof value !== 'string') return true;
    return oacIdentifiers.has(value);
  }

  private isS3Origin(origin: any, s3Config: any): boolean {
    if (s3Config) return true;
    return isS3OriginDomain(origin.domain_name);
  }

  private firstOrSelf(value: any): any {
    if (Array.isArray(value)) return value[0];
    return value;
  }
}
