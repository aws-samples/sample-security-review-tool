import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { Lambda015Adapter } from './lambda-015.adapter.js';

const LATEST_TAG_SCENARIO = 'use-specific-version-tag';
const LATEST_TAG = 'latest';

export class Lambda015Control extends SecurityControl<Lambda015Adapter> {
  constructor() {
    super({
      id: 'LAMBDA-015',
      priority: 'HIGH',
      description: 'Lambda container images must use a specific version tag instead of latest',
      remediationScenarios: [
        {
          scenario: LATEST_TAG_SCENARIO,
          intent:
            'Pin the Lambda container image reference to an immutable, specific version identifier (such as a semantic version tag or image digest) so that the deployed image content cannot change without an explicit configuration update.',
        },
      ],
    });
  }

  protected evaluate(adapter: Lambda015Adapter): ControlFinding | null {
    const imageUri = adapter.getImageUri();
    if (!imageUri) return null;

    if (this.usesExplicitLatestTag(imageUri)) {
      return {
        scenario: LATEST_TAG_SCENARIO,
        issue: "Lambda function container image reference uses the mutable 'latest' tag instead of a specific version identifier",
      };
    }

    if (this.hasNoTagOrDigest(imageUri)) {
      return {
        scenario: LATEST_TAG_SCENARIO,
        issue: "Lambda function container image reference omits a tag and digest, causing it to resolve to the mutable 'latest' image at pull time",
      };
    }

    return null;
  }

  private usesExplicitLatestTag(imageUri: string): boolean {
    const tag = this.extractTag(imageUri);
    if (!tag) return false;
    return tag.toLowerCase() === LATEST_TAG;
  }

  private hasNoTagOrDigest(imageUri: string): boolean {
    if (imageUri.includes('@')) return false;
    return this.extractTag(imageUri) === undefined;
  }

  private extractTag(imageUri: string): string | undefined {
    const digestIndex = imageUri.indexOf('@');
    if (digestIndex !== -1) return undefined;

    const lastSlashIndex = imageUri.lastIndexOf('/');
    const lastSegment = lastSlashIndex === -1 ? imageUri : imageUri.slice(lastSlashIndex + 1);
    const colonIndex = lastSegment.indexOf(':');
    if (colonIndex === -1) return undefined;
    return lastSegment.slice(colonIndex + 1);
  }
}

export const lambda015Control = new Lambda015Control();
