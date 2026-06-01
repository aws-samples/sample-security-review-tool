import { ControlAdapter } from '../../../controls/types.js';

export interface CustomOriginInspection {
  readonly originId: string;
  readonly protocolPolicy: string | undefined;
  readonly sslProtocols: readonly string[] | undefined;
  readonly sslProtocolsUnresolvable: boolean;
}

export interface Cf005Adapter extends ControlAdapter {
  getCustomOrigins(): CustomOriginInspection[];
}
