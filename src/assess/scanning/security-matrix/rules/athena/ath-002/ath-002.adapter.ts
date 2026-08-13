import { ControlAdapter } from '../../../controls/types.js';

export interface Ath002Adapter extends ControlAdapter {
  /** True when the bound resource is an Athena WorkGroup (the only resource this rule reports on). */
  isWorkGroup(): boolean;

  /**
   * True when the workgroup stores query results in Athena managed storage, meaning there is
   * no customer-owned results bucket whose policy could be inspected.
   */
  usesManagedQueryResultsStorage(): boolean;

  /** True when the workgroup declares a query-result output location. */
  hasOutputLocation(): boolean;

  /**
   * True when the resolved output-location bucket is protected by a policy that denies
   * requests made without TLS, or when the bucket cannot be resolved (unknown => pass).
   */
  outputBucketEnforcesTls(): boolean;
}
