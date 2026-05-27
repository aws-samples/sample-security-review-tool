import { ControlAdapter } from '../../../controls/types.js';

export interface Cf004Adapter extends ControlAdapter {
  hasDefaultCacheBehaviorViewerProtocolPolicy(): boolean;
  defaultCacheBehaviorAllowsHttp(): boolean;
  hasAdditionalCacheBehaviorAllowingHttp(): boolean;
}
