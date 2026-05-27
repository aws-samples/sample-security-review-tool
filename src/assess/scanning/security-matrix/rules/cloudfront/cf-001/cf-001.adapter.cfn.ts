import { AdapterFactory, CfnContext } from '../../../controls/types.js';
import { Cf001Adapter } from './cf-001.adapter.js';
import { isInsecureMinimumProtocolVersion } from './cf-001.protocol-versions.js';

export class Cf001CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::CloudFront::Distribution'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): Cf001CfnAdapter {
    return new Cf001CfnAdapter(context);
  }
}

class Cf001CfnAdapter implements Cf001Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  usesDefaultCloudFrontCertificate(): boolean {
    const viewerCertificate = this.getViewerCertificate();
    if (!viewerCertificate || typeof viewerCertificate !== 'object') return false;
    return (viewerCertificate as Record<string, unknown>).CloudFrontDefaultCertificate === true;
  }

  hasViewerCertificate(): boolean {
    const viewerCertificate = this.getViewerCertificate();
    return viewerCertificate !== undefined && viewerCertificate !== null;
  }

  hasMinimumProtocolVersion(): boolean {
    return this.getRawMinimumProtocolVersion() !== undefined;
  }

  hasInsecureMinimumProtocolVersion(): boolean {
    const minimumProtocolVersion = this.getResolvedMinimumProtocolVersion();
    if (minimumProtocolVersion === undefined) return false;
    return isInsecureMinimumProtocolVersion(minimumProtocolVersion);
  }

  private getResolvedMinimumProtocolVersion(): string | undefined {
    const value = this.getRawMinimumProtocolVersion();
    if (typeof value !== 'string' || value.length === 0) return undefined;
    return value;
  }

  private getRawMinimumProtocolVersion(): unknown {
    const viewerCertificate = this.getViewerCertificate();
    if (!viewerCertificate || typeof viewerCertificate !== 'object') return undefined;
    const minimumProtocolVersion = (viewerCertificate as Record<string, unknown>).MinimumProtocolVersion;
    if (minimumProtocolVersion === undefined || minimumProtocolVersion === null) return undefined;
    if (typeof minimumProtocolVersion === 'string' && minimumProtocolVersion.length === 0) return undefined;
    return minimumProtocolVersion;
  }

  private getViewerCertificate(): unknown {
    const distributionConfig = this.ctx.resource.Properties?.DistributionConfig;
    if (!distributionConfig || typeof distributionConfig !== 'object') return undefined;
    return (distributionConfig as Record<string, unknown>).ViewerCertificate;
  }
}
