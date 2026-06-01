import { AdapterFactory, CfnContext } from '../../../controls/types.js';
import { Cf005Adapter, CustomOriginInspection } from './cf-005.adapter.js';

export class Cf005CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::CloudFront::Distribution'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): Cf005CfnAdapter {
    return new Cf005CfnAdapter(context);
  }
}

interface SslProtocolsReadResult {
  readonly protocols: readonly string[] | undefined;
  readonly unresolvable: boolean;
}

class Cf005CfnAdapter implements Cf005Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  getCustomOrigins(): CustomOriginInspection[] {
    const props = (this.ctx.resource.Properties ?? {}) as Record<string, unknown>;
    const distributionConfig = props['DistributionConfig'] as Record<string, unknown> | undefined;
    const origins = distributionConfig?.['Origins'];
    if (!Array.isArray(origins)) return [];

    const inspections: CustomOriginInspection[] = [];
    for (const origin of origins) {
      if (!origin || typeof origin !== 'object') continue;
      const originRecord = origin as Record<string, unknown>;
      const customOriginConfig = originRecord['CustomOriginConfig'] as Record<string, unknown> | undefined;
      if (!customOriginConfig) continue;
      const sslRead = this.readSslProtocols(customOriginConfig['OriginSSLProtocols']);
      inspections.push({
        originId: typeof originRecord['Id'] === 'string' ? (originRecord['Id'] as string) : '',
        protocolPolicy: typeof customOriginConfig['OriginProtocolPolicy'] === 'string'
          ? (customOriginConfig['OriginProtocolPolicy'] as string)
          : undefined,
        sslProtocols: sslRead.protocols,
        sslProtocolsUnresolvable: sslRead.unresolvable,
      });
    }
    return inspections;
  }

  private readSslProtocols(value: unknown): SslProtocolsReadResult {
    if (value === undefined || value === null) {
      return { protocols: undefined, unresolvable: false };
    }
    if (!Array.isArray(value)) {
      return { protocols: undefined, unresolvable: true };
    }
    const allStrings = value.every(entry => typeof entry === 'string');
    if (!allStrings) {
      return { protocols: undefined, unresolvable: true };
    }
    return { protocols: value as string[], unresolvable: false };
  }
}
