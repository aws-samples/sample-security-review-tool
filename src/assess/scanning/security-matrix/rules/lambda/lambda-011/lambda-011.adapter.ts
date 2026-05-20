import { ControlAdapter } from '../../../controls/types.js';

export interface Lambda011Adapter extends ControlAdapter {
  hasMonitoringAlarm(): boolean;
}
