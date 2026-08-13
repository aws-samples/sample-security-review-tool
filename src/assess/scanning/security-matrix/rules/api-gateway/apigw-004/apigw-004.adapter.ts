import { ControlAdapter } from '../../../controls/types.js';

export interface Apigw004Adapter extends ControlAdapter {
  /** True when the method/route only serves the OPTIONS (CORS preflight) verb. */
  isOptionsMethod(): boolean;
  /** True when this is a WebSocket route other than $connect, which cannot carry authorization. */
  isWebSocketRouteWithoutAuthorizationSupport(): boolean;
  /** True when no authorization configuration of any kind is present. */
  hasNoAuthorizationConfiguration(): boolean;
}
