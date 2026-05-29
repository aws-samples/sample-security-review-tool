import { ControlAdapter } from '../../../controls/types.js';

export interface S3001Adapter extends ControlAdapter {
  hasLoggingConfigured(): boolean;
  isLogDestination(): boolean;
}
