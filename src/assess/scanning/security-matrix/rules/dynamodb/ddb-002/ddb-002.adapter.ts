import { ControlAdapter } from '../../../controls/types.js';

export interface Ddb002Adapter extends ControlAdapter {
  hasTrailCapturingDynamoDbDataEvents(): boolean;
}
