import { PostHog } from 'posthog-node';
import { SrtLogger } from '../logging/srt-logger.js';

export class PostHogClient {
    private static instance: PostHogClient;
    private client: PostHog;

    private constructor() {
        this.client = new PostHog(
            'phc_kghLn9QcwN3fkvHY94BPUBmB8QEAyvx9pyeJ9znVfXcP',
            { host: 'https://us.i.posthog.com' }
        );
    }

    public static initialize(): void {
        if (!PostHogClient.instance) {
            PostHogClient.instance = new PostHogClient();
        }
    }

    private static getInstance(): PostHogClient {
        if (!PostHogClient.instance) {
            throw new Error('PostHogClient not initialized. Call PostHogClient.initialize() first.');
        }
        return PostHogClient.instance;
    }

    public static capture(distinctId: string, event: string, properties?: Record<string, unknown>): void {
        PostHogClient.getInstance().client.capture({ distinctId, event, properties });
    }

    public static async shutdown(): Promise<void> {
        try {
            await PostHogClient.getInstance().client.shutdown();
        } catch (error) {
            SrtLogger.logError('Failed to shutdown PostHog client', error);
        }
    }
}
