import { ControlAdapter } from '../../../controls/types.js';

export type EncryptionOption = 'SSE_S3' | 'SSE_KMS' | 'CSE_KMS';

export interface Ath001Adapter extends ControlAdapter {
  /** The configured query result encryption option, or undefined when none is specified. */
  getEncryptionOption(): string | undefined;
  /** True when a KMS key is specified for query result encryption. */
  hasKmsKey(): boolean;
  /** True when the encryption settings cannot be determined (unresolved intrinsics). */
  isEncryptionUnknown(): boolean;
  /**
   * True when the workgroup forces its own settings over client-submitted settings,
   * false when it does not, and undefined when the setting cannot be determined.
   */
  isConfigurationEnforced(): boolean | undefined;
}
