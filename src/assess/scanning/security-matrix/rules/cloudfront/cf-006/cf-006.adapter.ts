import { ControlAdapter } from '../../../controls/types.js';

export type OacEligibleOriginType = 's3' | 'lambda-url' | 'mediastore' | 'mediapackagev2';

export interface S3OriginWithoutAccessControl {
  readonly originId: string;
  readonly originType: OacEligibleOriginType;
}

export interface Cf006Adapter extends ControlAdapter {
  findS3OriginsWithoutAccessControl(): S3OriginWithoutAccessControl[];
}
