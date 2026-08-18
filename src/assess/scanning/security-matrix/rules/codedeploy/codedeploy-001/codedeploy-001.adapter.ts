import { ControlAdapter } from '../../../controls/types.js';

export interface Codedeploy001Adapter extends ControlAdapter {
  /**
   * True when the deployment group lists at least one CloudWatch alarm,
   * false when it lists none, and undefined when the configuration cannot be determined.
   */
  hasConfiguredAlarms(): boolean | undefined;
}
