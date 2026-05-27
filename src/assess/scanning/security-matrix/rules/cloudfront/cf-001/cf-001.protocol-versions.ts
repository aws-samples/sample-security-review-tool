/**
 * Known CloudFront viewer-certificate security policies that enforce a
 * minimum TLS version of 1.2 or higher. Any other value (including future,
 * unrecognized, or pre-1.2 policies) must be treated as insecure because it
 * cannot be confirmed to enforce TLS 1.2+.
 */
const SECURE_MINIMUM_PROTOCOL_VERSIONS: ReadonlySet<string> = new Set([
  'TLSv1.2_2018',
  'TLSv1.2_2019',
  'TLSv1.2_2021',
  'TLSv1.2_2025',
  'TLSv1.3_2025',
]);

export function isInsecureMinimumProtocolVersion(version: string): boolean {
  return !SECURE_MINIMUM_PROTOCOL_VERSIONS.has(version);
}
