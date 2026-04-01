import { PostHog } from 'posthog-node';
import { SrtLogger } from '../logging/srt-logger.js';

export class PostHogClient {
    private static instance: PostHogClient;
    private static enabled = true;
    private static installationId: string;
    private static projectId: string | null = null;
    private client: PostHog;

    private constructor() {
        this.client = new PostHog(
            'phc_kghLn9QcwN3fkvHY94BPUBmB8QEAyvx9pyeJ9znVfXcP',
            { host: 'https://us.i.posthog.com' }
        );
    }

    public static initialize(installationId: string, projectId?: string): void {
        PostHogClient.installationId = installationId;
        PostHogClient.projectId = projectId ?? null;
        if (!PostHogClient.instance) {
            PostHogClient.instance = new PostHogClient();
        }
    }

    public static capture(event: string, properties?: Record<string, unknown>): void {
        if (!PostHogClient.instance || !PostHogClient.enabled || process.env.SRT_TELEMETRY_DISABLED === '1') {
            return;
        }

        const enrichedProperties = {
            ...properties,
            ...(PostHogClient.projectId && { project_id: PostHogClient.projectId })
        };

        PostHogClient.instance.client.capture({
            distinctId: PostHogClient.installationId,
            event,
            properties: enrichedProperties
        });
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
