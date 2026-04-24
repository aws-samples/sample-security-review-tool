import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { BedrockConfig } from '../../../../src/config/aws/bedrock-config.js';
import { SrtLogger } from '../../../../src/shared/logging/srt-logger.js';

export function bootstrapBedrock(): void {
    const logsFolderPath = path.join(os.homedir(), '.srt', 'logs');
    fs.mkdirSync(logsFolderPath, { recursive: true });
    SrtLogger.initialize(logsFolderPath);

    const envRegion = process.env.AWS_REGION ?? process.env.AWS_DEFAULT_REGION;
    const envProfile = process.env.AWS_PROFILE ?? 'default';
    if (envRegion) {
        BedrockConfig.initialize(envProfile, envRegion);
        return;
    }

    const configPath = findSrtConfigPath();
    if (configPath) {
        const config = JSON.parse(fs.readFileSync(configPath, 'utf8')) as { AWS_PROFILE?: string; AWS_REGION?: string };
        if (config.AWS_REGION) {
            BedrockConfig.initialize(config.AWS_PROFILE ?? 'default', config.AWS_REGION);
            return;
        }
    }

    throw new Error(
        'Could not determine AWS profile/region for Bedrock. Set AWS_REGION (and optionally AWS_PROFILE) '
        + 'in your environment, or point SRT_CONFIG_PATH at an existing srtconfig.json produced by `srt config`.',
    );
}

function findSrtConfigPath(): string | null {
    const candidates = [
        process.env.SRT_CONFIG_PATH,
        path.join(os.homedir(), '.local', 'bin', 'srtconfig.json'),
        path.join(os.homedir(), 'bin', 'srtconfig.json'),
        path.join('/usr/local/bin', 'srtconfig.json'),
    ].filter((candidate): candidate is string => typeof candidate === 'string');

    for (const candidate of candidates) {
        if (fs.existsSync(candidate)) return candidate;
    }
    return null;
}
