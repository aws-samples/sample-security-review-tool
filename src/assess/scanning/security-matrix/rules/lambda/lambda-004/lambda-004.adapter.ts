import { ControlAdapter } from '../../../controls/types.js';

export interface Lambda004Adapter extends ControlAdapter {
  hasTracingConfigured(): boolean;
}
