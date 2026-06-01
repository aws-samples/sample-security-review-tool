import { AdapterFactory, TerraformResource, TfContext } from '../../../controls/types.js';
import { Cf006Adapter, OacEligibleOriginType, S3OriginWithoutAccessControl } from './cf-006.adapter.js';

const S3_DOMAIN_PATTERN = /\.s3[.-][^.]+\.amazonaws\.com$/i;
const S3_GLOBAL_DOMAIN_PATTERN = /\.s3\.amazonaws\.com$/i;
const LAMBDA_URL_DOMAIN_PATTERN = /\.lambda-url\.[^.]+\.on\.aws$/i;
const MEDIASTORE_DOMAIN_PATTERN = /\.data\.mediastore\.[^.]+\.amazonaws\.com$/i;
const MEDIAPACKAGE_V2_DOMAIN_PATTERN = /\.egress\.mediapackagev2\.[^.]+\.amazonaws\.com$/i;
const S3_BUCKET_ADDRESS_PREFIX = 'aws_s3_bucket.';
const OAC_RESOURCE_TYPE = 'aws_cloudfront_origin_access_control';
const OAC_ADDRESS_PREFIX = 'aws_cloudfront_origin_access_control.';

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

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
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
    const values = (this.ctx.resource.values ?? {}) as Record<string, unknown>;
    const origins = values['origin'];
    if (!Array.isArray(origins)) return [];
    return origins.filter((o): o is Record<string, unknown> => typeof o === 'object' && o !== null);
  }

  private detectOacEligibleType(origin: Record<string, unknown>): OacEligibleOriginType | null {
    if (this.isS3Origin(origin)) return 's3';
    const domainName = origin['domain_name'];
    if (typeof domainName !== 'string') return null;
    if (LAMBDA_URL_DOMAIN_PATTERN.test(domainName)) return 'lambda-url';
    if (MEDIASTORE_DOMAIN_PATTERN.test(domainName)) return 'mediastore';
    if (MEDIAPACKAGE_V2_DOMAIN_PATTERN.test(domainName)) return 'mediapackagev2';
    return null;
  }

  private isS3Origin(origin: Record<string, unknown>): boolean {
    if (origin['s3_origin_config'] !== undefined) return true;
    const domainName = origin['domain_name'];
    if (typeof domainName !== 'string') return false;
    if (this.isLiteralS3Domain(domainName)) return true;
    return this.referencesS3Bucket(domainName);
  }

  private isLiteralS3Domain(domainName: string): boolean {
    return S3_DOMAIN_PATTERN.test(domainName) || S3_GLOBAL_DOMAIN_PATTERN.test(domainName);
  }

  private referencesS3Bucket(domainName: string): boolean {
    if (domainName.startsWith(S3_BUCKET_ADDRESS_PREFIX)) {
      return this.findResourceByAddress(domainName)?.type === 'aws_s3_bucket';
    }
    return this.findBucketByLiteralName(domainName) !== undefined;
  }

  private findResourceByAddress(address: string): TerraformResource | undefined {
    return this.ctx.allResources.find(r => r.address === address);
  }

  private findBucketByLiteralName(name: string): TerraformResource | undefined {
    return this.ctx.allResources.find(r => {
      if (r.type !== 'aws_s3_bucket') return false;
      const bucketName = (r.values as Record<string, unknown> | undefined)?.['bucket'];
      return typeof bucketName === 'string' && bucketName === name;
    });
  }

  /**
   * The plan reader records origin_access_control_id as null when the value
   * is unknown at plan time (e.g. depends on a variable). Per resolved
   * decision, we cannot assert non-compliance for an unresolvable value.
   */
  private hasUnresolvableOriginAccessControl(origin: Record<string, unknown>): boolean {
    return origin['origin_access_control_id'] === null;
  }

  /**
   * The origin_access_control_id is considered to provide access control
   * only when it resolves to an aws_cloudfront_origin_access_control
   * resource managed in this plan — either via address reference or by
   * matching a literal id attribute. A dangling reference (string that
   * matches no OAC resource) is non-compliant per REQ-06.
   */
  private hasResolvedOriginAccessControl(origin: Record<string, unknown>): boolean {
    const oacId = origin['origin_access_control_id'];
    if (typeof oacId !== 'string' || oacId.trim().length === 0) return false;
    return this.referencesOacResource(oacId);
  }

  private referencesOacResource(oacId: string): boolean {
    if (oacId.startsWith(OAC_ADDRESS_PREFIX)) {
      return this.findResourceByAddress(oacId)?.type === OAC_RESOURCE_TYPE;
    }
    return this.findOacByLiteralId(oacId) !== undefined;
  }

  private findOacByLiteralId(id: string): TerraformResource | undefined {
    return this.ctx.allResources.find(r => {
      if (r.type !== OAC_RESOURCE_TYPE) return false;
      const values = (r.values as Record<string, unknown> | undefined) ?? {};
      const candidates = [values['id'], values['name']];
      return candidates.some(c => typeof c === 'string' && c === id);
    });
  }

  private hasLegacyOriginAccessIdentity(origin: Record<string, unknown>): boolean {
    const s3Config = origin['s3_origin_config'];
    if (!Array.isArray(s3Config) || s3Config.length === 0) return false;
    return s3Config.some(block => {
      if (typeof block !== 'object' || block === null) return false;
      const oai = (block as Record<string, unknown>)['cloudfront_access_identity_path'];
      return typeof oai === 'string' && oai.trim().length > 0;
    });
  }

  private getOriginId(origin: Record<string, unknown>): string {
    const id = origin['origin_id'];
    return typeof id === 'string' ? id : '';
  }
}
