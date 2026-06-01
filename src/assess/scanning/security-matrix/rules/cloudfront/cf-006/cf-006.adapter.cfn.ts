import { AdapterFactory, CfnContext, Template } from '../../../controls/types.js';
import { Cf006Adapter, OacEligibleOriginType, S3OriginWithoutAccessControl } from './cf-006.adapter.js';

const S3_DOMAIN_PATTERN = /\.s3[.-][^.]+\.amazonaws\.com$/i;
const S3_GLOBAL_DOMAIN_PATTERN = /\.s3\.amazonaws\.com$/i;
const LAMBDA_URL_DOMAIN_PATTERN = /\.lambda-url\.[^.]+\.on\.aws$/i;
const MEDIASTORE_DOMAIN_PATTERN = /\.data\.mediastore\.[^.]+\.amazonaws\.com$/i;
const MEDIAPACKAGE_V2_DOMAIN_PATTERN = /\.egress\.mediapackagev2\.[^.]+\.amazonaws\.com$/i;
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

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  findS3OriginsWithoutAccessControl(): S3OriginWithoutAccessControl[] {
    return this.getOrigins()
      .map(origin => this.classifyUnprotectedOrigin(origin))
      .filter((entry): entry is S3OriginWithoutAccessControl => entry !== null);
  }

  private classifyUnprotectedOrigin(origin: Record<string, unknown>): S3OriginWithoutAccessControl | null {
    const originType = this.detectOacEligibleType(origin);
    if (originType === null) return null;
    if (this.hasUnresolvableOriginAccessControl(origin)) return null;
    if (this.hasResolvedOriginAccessControl(origin)) return null;
    if (originType === 's3' && this.hasLegacyOriginAccessIdentity(origin)) return null;
    return { originId: this.getOriginId(origin), originType };
  }

  private getOrigins(): Record<string, unknown>[] {
    const config = this.ctx.resource.Properties?.['DistributionConfig'] as Record<string, unknown> | undefined;
    const origins = config?.['Origins'];
    if (!Array.isArray(origins)) return [];
    return origins.filter((o): o is Record<string, unknown> => typeof o === 'object' && o !== null);
  }

  private detectOacEligibleType(origin: Record<string, unknown>): OacEligibleOriginType | null {
    if (this.isS3Origin(origin)) return 's3';
    const domainName = origin['DomainName'];
    if (typeof domainName !== 'string') return null;
    if (LAMBDA_URL_DOMAIN_PATTERN.test(domainName)) return 'lambda-url';
    if (MEDIASTORE_DOMAIN_PATTERN.test(domainName)) return 'mediastore';
    if (MEDIAPACKAGE_V2_DOMAIN_PATTERN.test(domainName)) return 'mediapackagev2';
    return null;
  }

  private isS3Origin(origin: Record<string, unknown>): boolean {
    if (origin['S3OriginConfig'] !== undefined) return true;
    const domainName = origin['DomainName'];
    if (typeof domainName !== 'string') return false;
    if (this.isLiteralS3Domain(domainName)) return true;
    return this.referencesS3Bucket(domainName);
  }

  private isLiteralS3Domain(domainName: string): boolean {
    return S3_DOMAIN_PATTERN.test(domainName) || S3_GLOBAL_DOMAIN_PATTERN.test(domainName);
  }

  private referencesS3Bucket(domainName: string): boolean {
    const resources = this.ctx.template.Resources ?? ({} as NonNullable<Template['Resources']>);
    const referenced = resources[domainName];
    return referenced?.Type === 'AWS::S3::Bucket';
  }

  /**
   * The OriginAccessControlId was provided as an unresolved intrinsic
   * (e.g. Fn::If, Fn::ImportValue). Its real value depends on a condition,
   * cross-stack export, or other runtime input we cannot evaluate here.
   * Per resolved decision, we cannot assert non-compliance in this case.
   */
  private hasUnresolvableOriginAccessControl(origin: Record<string, unknown>): boolean {
    const oacId = origin['OriginAccessControlId'];
    return this.isUnresolvedIntrinsic(oacId);
  }

  private isUnresolvedIntrinsic(value: unknown): boolean {
    return typeof value === 'object' && value !== null;
  }

  /**
   * The OriginAccessControlId is considered to provide access control only
   * when it resolves to an OAC resource defined in this template. A dangling
   * reference (string that matches no OAC logical ID) is non-compliant per
   * the resolved decision for REQ-06.
   */
  private hasResolvedOriginAccessControl(origin: Record<string, unknown>): boolean {
    const oacId = origin['OriginAccessControlId'];
    if (typeof oacId !== 'string' || oacId.trim().length === 0) return false;
    return this.referencesOacResource(oacId);
  }

  private referencesOacResource(oacId: string): boolean {
    const resources = this.ctx.template.Resources ?? ({} as NonNullable<Template['Resources']>);
    const referenced = resources[oacId];
    return referenced?.Type === OAC_RESOURCE_TYPE;
  }

  private hasLegacyOriginAccessIdentity(origin: Record<string, unknown>): boolean {
    const s3Config = origin['S3OriginConfig'] as Record<string, unknown> | undefined;
    if (!s3Config) return false;
    const oai = s3Config['OriginAccessIdentity'];
    return typeof oai === 'string' && oai.trim().length > 0;
  }

  private getOriginId(origin: Record<string, unknown>): string {
    const id = origin['Id'];
    return typeof id === 'string' ? id : '';
  }
}
