import { ControlAdapter } from '../../../controls/types.js';

export interface Apigw001Adapter extends ControlAdapter {
  hasAccessLogging(): boolean;
  hasProperLogRetention(): boolean;
}
