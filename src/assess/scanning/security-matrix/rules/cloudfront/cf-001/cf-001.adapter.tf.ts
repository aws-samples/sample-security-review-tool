import { AdapterFactory, TfContext } from '../../../controls/types.js';
import { Cf001Adapter } from './cf-001.adapter.js';
import { isInsecureMinimumProtocolVersion } from './cf-001.protocol-versions.js';

export class Cf001TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = ['aws_cloudfront_distribution'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): Cf001TfAdapter {
    return new Cf001TfAdapter(context);
  }
}

class Cf001TfAdapter implements Cf001Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  usesDefaultCloudFrontCertificate(): boolean {
    const block = this.getViewerCertificateBlock();
    if (!block) return false;
    return block.cloudfront_default_certificate === true;
  }

  hasViewerCertificate(): boolean {
    return this.getViewerCertificateBlock() !== undefined;
  }

  hasMinimumProtocolVersion(): boolean {
    return this.getMinimumProtocolVersion() !== undefined;
  }

  hasInsecureMinimumProtocolVersion(): boolean {
    const minimumProtocolVersion = this.getMinimumProtocolVersion();
    if (minimumProtocolVersion === undefined) return false;
    return isInsecureMinimumProtocolVersion(minimumProtocolVersion);
  }

  private getMinimumProtocolVersion(): string | undefined {
    const block = this.getViewerCertificateBlock();
    if (!block) return undefined;
    const minimumProtocolVersion = block.minimum_protocol_version;
    if (typeof minimumProtocolVersion !== 'string' || minimumProtocolVersion.length === 0) return undefined;
    return minimumProtocolVersion;
  }

  private getViewerCertificateBlock(): Record<string, unknown> | undefined {
    const values = (this.ctx.resource.values ?? {}) as Record<string, unknown>;
    const viewerCertificate = values.viewer_certificate;
    if (viewerCertificate === undefined || viewerCertificate === null) return undefined;
    if (Array.isArray(viewerCertificate)) {
      const first = viewerCertificate[0];
      if (!first || typeof first !== 'object') return undefined;
      return first as Record<string, unknown>;
    }
    if (typeof viewerCertificate === 'object') return viewerCertificate as Record<string, unknown>;
    return undefined;
  }
}
