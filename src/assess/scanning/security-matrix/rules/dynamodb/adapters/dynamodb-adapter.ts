import { ControlAdapter } from '../../../controls/types.js';

export interface DynamodbAdapter extends ControlAdapter {
  hasDataPlaneCoverage(): boolean;
}
