import { AdapterFactory, TfContext } from '../../../controls/types.js';
import { Cf005Adapter, CustomOriginInspection } from './cf-005.adapter.js';

export class Cf005TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = ['aws_cloudfront_distribution'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): Cf005TfAdapter {
    return new Cf005TfAdapter(context);
  }
}

interface SslProtocolsReadResult {
  readonly protocols: readonly string[] | undefined;
  readonly unresolvable: boolean;
}

class Cf005TfAdapter implements Cf005Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  getCustomOrigins(): CustomOriginInspection[] {
    const values = (this.ctx.resource.values ?? {}) as Record<string, unknown>;
    const origins = values['origin'];
    if (!Array.isArray(origins)) return [];

    const inspections: CustomOriginInspection[] = [];
    for (const origin of origins) {
      if (!origin || typeof origin !== 'object') continue;
      const originRecord = origin as Record<string, unknown>;
      const customOriginConfig = this.firstBlock(originRecord['custom_origin_config']);
      if (!customOriginConfig) continue;
      const hasSslKey = Object.prototype.hasOwnProperty.call(customOriginConfig, 'origin_ssl_protocols');
      const sslRead = this.readSslProtocols(customOriginConfig['origin_ssl_protocols'], hasSslKey);
      inspections.push({
        originId: typeof originRecord['origin_id'] === 'string' ? (originRecord['origin_id'] as string) : '',
        protocolPolicy: typeof customOriginConfig['origin_protocol_policy'] === 'string'
          ? (customOriginConfig['origin_protocol_policy'] as string)
          : undefined,
        sslProtocols: sslRead.protocols,
        sslProtocolsUnresolvable: sslRead.unresolvable,
      });
    }
    return inspections;
  }

  private firstBlock(value: unknown): Record<string, unknown> | undefined {
    if (Array.isArray(value) && value.length > 0 && typeof value[0] === 'object' && value[0] !== null) {
      return value[0] as Record<string, unknown>;
    }
    if (value && typeof value === 'object') {
      return value as Record<string, unknown>;
    }
    return undefined;
  }

  private readSslProtocols(value: unknown, hasKey: boolean): SslProtocolsReadResult {
    if (value === null) {
      return { protocols: undefined, unresolvable: hasKey };
    }
    if (value === undefined) {
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
