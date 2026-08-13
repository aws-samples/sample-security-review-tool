import { ControlAdapter } from '../../../controls/types.js';

export interface Apigw008Adapter extends ControlAdapter {
  /**
   * True when response caching is enabled for at least one method whose
   * cached data is known to be unencrypted.
   */
  hasUnencryptedCachedMethod(): boolean;
}

/** Shape of a single method-level caching configuration, IaC-agnostic. */
export interface CachedMethodSetting {
  readonly cachingEnabled: unknown;
  readonly cacheDataEncrypted: unknown;
  /** True when the setting applies to every method of the stage. */
  readonly isCatchAll?: boolean;
}

const isTrue = (value: unknown): boolean => value === true || value === 'true';

/**
 * Unresolved values are either unresolved IaC intrinsics (objects) or values
 * that are unknown at plan time (null). Neither can be asserted as unencrypted.
 */
const isUnresolved = (value: unknown): boolean => value === null || typeof value === 'object';

const isUnstated = (value: unknown): boolean => value === undefined;

/** A catch-all setting enabling encryption covers methods that state no value. */
const hasEncryptedCatchAll = (settings: readonly CachedMethodSetting[]): boolean =>
  settings.some(setting => setting.isCatchAll === true && isTrue(setting.cacheDataEncrypted));

function isKnownUnencrypted(value: unknown, inheritsEncryption: boolean): boolean {
  if (isTrue(value) || isUnresolved(value)) return false;
  return !(inheritsEncryption && isUnstated(value));
}

export function hasUnencryptedCaching(settings: readonly CachedMethodSetting[]): boolean {
  const inheritsEncryption = hasEncryptedCatchAll(settings);
  return settings.some(
    setting => isTrue(setting.cachingEnabled) && isKnownUnencrypted(setting.cacheDataEncrypted, inheritsEncryption),
  );
}
