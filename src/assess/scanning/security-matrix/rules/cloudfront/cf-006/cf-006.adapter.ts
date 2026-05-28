import { ControlAdapter } from '../../../controls/types.js';

export interface UnprotectedS3Origin {
  readonly originId: string;
}

export interface UnprotectedOacEligibleOrigin {
  readonly originId: string;
}

export interface Cf006Adapter extends ControlAdapter {
  readonly unprotectedS3Origins: UnprotectedS3Origin[];
  readonly unprotectedOacEligibleOrigins: UnprotectedOacEligibleOrigin[];
}

const S3_DOMAIN_PATTERN = /\.s3[.-][^/]*amazonaws\.com$/i;
const LAMBDA_URL_DOMAIN_PATTERN = /\.lambda-url\.[^.]+\.on\.aws$/i;
const MEDIASTORE_DOMAIN_PATTERN = /\.data\.mediastore\.[^.]+\.amazonaws\.com$/i;
const MEDIAPACKAGE_V2_DOMAIN_PATTERN = /\.egress\.mediapackagev2\.[^.]+\.amazonaws\.com$/i;

export function isS3OriginDomain(domainName: unknown): boolean {
  if (typeof domainName !== 'string') return false;
  return S3_DOMAIN_PATTERN.test(domainName);
}

export function isOacEligibleNonS3Domain(domainName: unknown): boolean {
  if (typeof domainName !== 'string') return false;
  return (
    LAMBDA_URL_DOMAIN_PATTERN.test(domainName) ||
    MEDIASTORE_DOMAIN_PATTERN.test(domainName) ||
    MEDIAPACKAGE_V2_DOMAIN_PATTERN.test(domainName)
  );
}

export function isMissing(value: unknown): boolean {
  if (value === undefined || value === null) return true;
  if (typeof value === 'string' && value.trim() === '') return true;
  return false;
}
