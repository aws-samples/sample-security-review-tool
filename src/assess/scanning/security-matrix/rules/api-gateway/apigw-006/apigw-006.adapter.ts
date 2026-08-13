import { ControlAdapter } from '../../../controls/types.js';

export interface Apigw006Adapter extends ControlAdapter {
  /** True when some method-level logging configuration exists for this stage. */
  hasMethodLoggingConfiguration(): boolean;

  /** True when a method-level logging configuration covers every method and path of the stage. */
  hasCatchAllCoverage(): boolean;

  /** True when the method-level logging configuration uses an accepted execution logging level. */
  hasAcceptedLoggingLevel(): boolean;

  /** True when any method-level logging configuration explicitly turns execution logging off. */
  hasLoggingDisabledForSomeMethod(): boolean;
}
