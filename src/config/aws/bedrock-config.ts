export class BedrockConfig {
    private static instance: BedrockConfig;
    private static errorMessage = 'BedrockConfig not initialized. Call BedrockConfig.initialize() first.';
    private static readonly DEFAULT_MODEL = {
        id: 'anthropic.claude-opus-4-5-20251101-v1:0',
        name: 'Claude Opus 4.5',
        crossRegionInference: true,
        promptCaching: true
    };

    private profile: string;
    private region: string;

    private constructor(profile: string, region: string) {
        this.profile = profile;
        this.region = region;
    }

    static initialize(profile: string, region: string) {
        BedrockConfig.instance = new BedrockConfig(profile, region);
    }

    static getProfile(): string {
        if (!BedrockConfig.instance) throw new Error(BedrockConfig.errorMessage);
        return BedrockConfig.instance.profile;
    }

    static getRegion(): string {
        if (!BedrockConfig.instance) throw new Error(BedrockConfig.errorMessage);
        return BedrockConfig.instance.region;
    }

    static getModel() {
        return BedrockConfig.DEFAULT_MODEL;
    }

    static getModelIdWithInferenceProfilePrefix(): string {
        if (!BedrockConfig.instance) throw new Error(BedrockConfig.errorMessage);
        
        const model = BedrockConfig.DEFAULT_MODEL;
        
        if (model.crossRegionInference === false) return model.id;

        const region = BedrockConfig.instance.region;

        if (region.startsWith('us-')) return `global.${model.id}`;
        if (region.startsWith('eu-')) return `eu.${model.id}`;
        if (region.startsWith('ap-')) return `apac.${model.id}`;
        if (region.startsWith('us-gov-')) return `us-gov.${model.id}`;

        return `global.${model.id}`;
    }
}
