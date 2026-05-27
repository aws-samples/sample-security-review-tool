import { ControlAdapter } from '../../../controls/types.js';

export interface Cf001Adapter extends ControlAdapter {
  usesDefaultCloudFrontCertificate(): boolean;
  hasViewerCertificate(): boolean;
  hasMinimumProtocolVersion(): boolean;
  hasInsecureMinimumProtocolVersion(): boolean;
}
