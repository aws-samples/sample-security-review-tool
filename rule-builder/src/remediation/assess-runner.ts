import * as os from 'node:os';
import * as fs from 'node:fs';
import { SrtLogger } from '../../../src/shared/logging/srt-logger.js';
import { BedrockConfig } from '../../../src/config/aws/bedrock-config.js';
import { AssessCoordinator } from '../../../src/assess/coordinator.js';

const logsFolderPath = `${os.homedir()}/.srt/logs`;
fs.mkdirSync(logsFolderPath, { recursive: true });
SrtLogger.initialize(logsFolderPath);
BedrockConfig.initialize('default', 'us-east-1');

async function main(): Promise<void> {
    const fixtureFolderPath = process.argv[2];
    if (!fixtureFolderPath) throw new Error('Usage: assess-runner <fixtureFolderPath>');

    const assessor = new AssessCoordinator(fixtureFolderPath, () => { });
    await assessor.assess('aws', false, false, false);
}

main().catch(error => {
    console.error(error.message);
    process.exit(1);
});
