import { BedrockRuntimeClient, ConverseCommand } from '@aws-sdk/client-bedrock-runtime';
import { fromNodeProviderChain } from '@aws-sdk/credential-providers';
import { FetchHttpHandler } from '@aws-sdk/fetch-http-handler';
import { BedrockConfig } from '../../config/aws/bedrock-config.js';

function getBedrockClient(): BedrockRuntimeClient {
	try {
		const clientConfig = {
			region: BedrockConfig.getRegion(),
			maxAttempts: 50,
			credentials: fromNodeProviderChain(BedrockConfig.getProfile() !== 'default' ? { profile: BedrockConfig.getProfile() } : {}),
			requestHandler: new FetchHttpHandler()  // This is necessary for Bun compatibility
		};

		return new BedrockRuntimeClient(clientConfig);
	} catch (error) {
		// Fall back to the original implementation if there's an error
		return new BedrockRuntimeClient({
			region: BedrockConfig.getRegion(),
			maxAttempts: 50,
			profile: BedrockConfig.getProfile()
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

	if (activeCallCount === 1 && onProgress) {
		globalProgressInterval = setInterval(() => {
			const randomMessage = PROGRESS_MESSAGES[Math.floor(Math.random() * PROGRESS_MESSAGES.length)];
			onProgress(`  › ${randomMessage}...`);
		}, 15000);
	}

	try {
		const model = BedrockConfig.getModel();
		const supportsPromptCaching = model.promptCaching;

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
			modelId: BedrockConfig.getModelIdWithInferenceProfilePrefix(),
			messages: [
				{
					role: "user",
					content
				}
			]
		});

		const client = getBedrockClient();
		const response = await client.send(cmd, { abortSignal: abortController.signal });

		return response.output?.message?.content?.[0].text?.toString() || "";
	} catch (error) {
		throw error;
	} finally {
		activeCallCount--;
		if (activeCallCount === 0 && globalProgressInterval !== null) {
			clearInterval(globalProgressInterval);
			globalProgressInterval = null;
		}
	}
}
