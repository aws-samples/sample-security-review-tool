import { ControlAdapter } from '../../../controls/types.js';

export interface S3001Adapter extends ControlAdapter {
  hasServerAccessLogging(): boolean;
  isLogDestination(): boolean;
}
