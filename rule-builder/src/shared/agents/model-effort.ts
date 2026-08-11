export type ModelEffort = 'low' | 'medium' | 'high' | 'xhigh' | 'max';

export const DEFAULT_EFFORT: ModelEffort = 'medium';

// Bedrock has no first-class effort parameter; it rides through Converse's provider passthrough,
// which the SDK populates from additionalRequestFields.
export function effortRequestFields(effort: ModelEffort): { output_config: { effort: ModelEffort } } {
    return { output_config: { effort } };
}
