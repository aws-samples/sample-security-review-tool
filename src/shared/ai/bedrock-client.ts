import { BedrockRuntimeClient, ConverseCommand } from '@aws-sdk/client-bedrock-runtime';
import { fromNodeProviderChain } from '@aws-sdk/credential-providers';
import { FetchHttpHandler } from '@aws-sdk/fetch-http-handler';
import { BedrockConfig } from '../../config/aws/bedrock-config.js';
import { SrtLogger } from '../logging/srt-logger.js';

function getBedrockClient(): BedrockRuntimeClient {
	const profile = BedrockConfig.getProfile();
	const region = BedrockConfig.getRegion();

	try {
		const clientConfig = {
			region,
			maxAttempts: 50,
			credentials: fromNodeProviderChain(profile !== 'default' ? { profile } : {}),
			requestHandler: new FetchHttpHandler()  // This is necessary for Bun compatibility
		};

		return new BedrockRuntimeClient(clientConfig);
	} catch (error) {
		return new BedrockRuntimeClient({
			region,
			maxAttempts: 50,
			profile
		});
	}
}

const PROGRESS_MESSAGES = [
	'Working',
	'Processing',
	'Computing',
	'Crunching the numbers',
	'Running calculations',
	'Executing',
	'Analyzing',
	'Thinking',
	'Evaluating',
	'Generating insights',
	'Building analysis'
];

let globalProgressInterval: NodeJS.Timeout | null = null;
let activeCallCount = 0;

export async function sendPrompt(prompt: string, context?: string, onProgress?: (message: string) => void): Promise<string> {
	const abortController = new AbortController();
	activeCallCount++;

	const model = BedrockConfig.getModel();
	const modelId = BedrockConfig.getModelIdWithInferenceProfilePrefix();
	const supportsPromptCaching = model.promptCaching;

	if (activeCallCount === 1 && onProgress) {
		globalProgressInterval = setInterval(() => {
			const randomMessage = PROGRESS_MESSAGES[Math.floor(Math.random() * PROGRESS_MESSAGES.length)];
			onProgress(`  › ${randomMessage}...`);
		}, 15000);
	}

	try {
		let content;

		if (context && supportsPromptCaching) {
			content = [
				{ text: context },
				{ cachePoint: { type: "default" as const } },
				{ text: prompt }
			];
		} else {
			content = [{ text: `${prompt}\n\n## CloudFormation Template\n\`\`\`\n${context}\n\`\`\`` }];
		}

		const cmd = new ConverseCommand({
			modelId,
			messages: [
				{
					role: "user",
					content
				}
			]
		});

		const client = getBedrockClient();
		const response = await client.send(cmd, { abortSignal: abortController.signal });

		const result = response.output?.message?.content?.[0].text?.toString() || "";

		return result;
	} catch (error) {
		SrtLogger.logError('Bedrock API call failed', error as Error, {
			modelId,
			promptLength: prompt.length,
			contextLength: context?.length || 0
		});
		throw error;
	} finally {
		activeCallCount--;
		if (activeCallCount === 0 && globalProgressInterval !== null) {
			clearInterval(globalProgressInterval);
			globalProgressInterval = null;
		}
	}
}
