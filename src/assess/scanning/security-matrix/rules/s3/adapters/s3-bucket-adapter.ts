import { BoundAdapter, IacRemediation } from '../../../controls/types.js';

export interface S3BucketAdapter extends BoundAdapter {
  isLogDestinationBucket(): boolean;
  getLoggingDestination(): string | null;
  isSelfLogging(): boolean;
  getRemediation(scenario: string): IacRemediation | null;
}
