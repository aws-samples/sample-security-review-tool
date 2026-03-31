export interface AwsProfile {
  name: string;
  region?: string;
  isDefault: boolean;
}

export interface ValidationResult {
  isValid: boolean;
  validCredentials: boolean;
  hasBedrockAccess: boolean;
  modelAccessible: boolean;
  credentialSource?: string;
  errors: string[];
}
