import { ControlAdapter } from '../../../controls/types.js';

export interface S3008Adapter extends ControlAdapter {
  readonly isBucket: boolean;
  readonly hasLifecycleConfiguration: boolean;
}
