import { PostHog } from 'posthog-node';
import { SrtLogger } from '../logging/srt-logger.js';

export class PostHogClient {
    private static instance: PostHogClient;
    private static enabled = true;
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

    public static setEnabled(enabled: boolean): void {
        PostHogClient.enabled = enabled;
    }

    public static isEnabled(): boolean {
        return PostHogClient.enabled;
    }

    public static capture(distinctId: string, event: string, properties?: Record<string, unknown>): void {
        if (!PostHogClient.enabled || process.env.SRT_TELEMETRY_DISABLED === '1') {
            return;
        }
        PostHogClient.getInstance().client.capture({ distinctId, event, properties });
    }

    public static async shutdown(): Promise<void> {
        if (!PostHogClient.instance) {
            return;
        }
        try {
            await PostHogClient.instance.client.shutdown();
        } catch (error) {
            SrtLogger.logError('Failed to shutdown PostHog client', error);
        }
    }
}
