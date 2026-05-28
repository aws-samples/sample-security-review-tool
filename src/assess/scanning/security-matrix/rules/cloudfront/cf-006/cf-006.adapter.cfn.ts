import { AdapterFactory, CfnContext } from '../../../controls/types.js';
import {
  Cf006Adapter,
  UnprotectedOacEligibleOrigin,
  UnprotectedS3Origin,
  isMissing,
  isOacEligibleNonS3Domain,
  isS3OriginDomain,
} from './cf-006.adapter.js';

const OAC_RESOURCE_TYPE = 'AWS::CloudFront::OriginAccessControl';

export class Cf006CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::CloudFront::Distribution'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): Cf006CfnAdapter {
    return new Cf006CfnAdapter(context);
  }
}

class Cf006CfnAdapter implements Cf006Adapter {
  readonly resourceId: string;
  readonly resourceType: string;
  readonly unprotectedS3Origins: UnprotectedS3Origin[];
  readonly unprotectedOacEligibleOrigins: UnprotectedOacEligibleOrigin[];

  constructor(ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
    const origins = this.getOrigins(ctx);
    const oacLogicalIds = this.collectOacLogicalIds(ctx);
    this.unprotectedS3Origins = this.findUnprotectedS3Origins(origins, oacLogicalIds);
    this.unprotectedOacEligibleOrigins = this.findUnprotectedOacEligibleOrigins(origins, oacLogicalIds);
  }

  private findUnprotectedS3Origins(origins: any[], oacLogicalIds: Set<string>): UnprotectedS3Origin[] {
    return origins
      .filter(origin => this.isUnprotectedS3Origin(origin, oacLogicalIds))
      .map(origin => ({ originId: String(origin?.Id ?? '') }));
  }

  private findUnprotectedOacEligibleOrigins(origins: any[], oacLogicalIds: Set<string>): UnprotectedOacEligibleOrigin[] {
    return origins
      .filter(origin => this.isUnprotectedNonS3OacEligibleOrigin(origin, oacLogicalIds))
      .map(origin => ({ originId: String(origin?.Id ?? '') }));
  }

  private getOrigins(ctx: CfnContext): any[] {
    const distributionConfig = (ctx.resource.Properties as any)?.DistributionConfig;
    const origins = distributionConfig?.Origins;
    return Array.isArray(origins) ? origins : [];
  }

  private collectOacLogicalIds(ctx: CfnContext): Set<string> {
    const ids = new Set<string>();
    const resources = (ctx.template as any)?.Resources ?? {};
    for (const [logicalId, resource] of Object.entries<any>(resources)) {
      if (resource?.Type === OAC_RESOURCE_TYPE) ids.add(logicalId);
    }
    return ids;
  }

  private isUnprotectedS3Origin(origin: any, oacLogicalIds: Set<string>): boolean {
    if (!origin || typeof origin !== 'object') return false;
    if (!this.isS3Origin(origin)) return false;
    if (this.hasLegacyOriginAccessIdentity(origin)) return false;
    return !this.hasResolvedOacReference(origin.OriginAccessControlId, oacLogicalIds);
  }

  private isUnprotectedNonS3OacEligibleOrigin(origin: any, oacLogicalIds: Set<string>): boolean {
    if (!origin || typeof origin !== 'object') return false;
    if (this.isS3Origin(origin)) return false;
    if (!isOacEligibleNonS3Domain(origin.DomainName)) return false;
    return !this.hasResolvedOacReference(origin.OriginAccessControlId, oacLogicalIds);
  }

  private hasLegacyOriginAccessIdentity(origin: any): boolean {
    return !isMissing(origin.S3OriginConfig?.OriginAccessIdentity);
  }

  private hasResolvedOacReference(value: unknown, oacLogicalIds: Set<string>): boolean {
    if (isMissing(value)) return false;
    if (this.isUnresolvedIntrinsic(value)) return true;
    if (typeof value !== 'string') return false;
    return oacLogicalIds.has(value);
  }

  private isUnresolvedIntrinsic(value: unknown): boolean {
    return typeof value === 'object' && value !== null;
  }

  private isS3Origin(origin: any): boolean {
    if (origin.S3OriginConfig !== undefined) return true;
    return isS3OriginDomain(origin.DomainName);
  }
}
