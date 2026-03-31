import chalk from 'chalk';
import { BedrockConfig } from '../../config/aws/bedrock-config.js';
import { ConfigManager, SRTConfig } from './config-manager.js';

export class ConfigLoader {
    static async load(): Promise<SRTConfig> {
        // Get the command being run 
        const command = process.argv[2];

        // Skip config loading for certain commands
        if (command === 'config' || command === 'update' || command === '--help' || command === '-h') {
            return {} as SRTConfig;
        }

        try {
            const configManager = new ConfigManager();
            const config = await configManager.loadConfig();

            if (!config) throw new Error('Invalid configuration');

            BedrockConfig.initialize(config.AWS_PROFILE, config.AWS_REGION);

            return config;
        } catch (error) {
            console.error(chalk.red('Configuration file not found or invalid.'));
            console.log(chalk.yellow('Please run the config command to set up your AWS configuration:'));
            console.log(chalk.cyan('  srt config'));

            process.exit(1);
        }
    }
}