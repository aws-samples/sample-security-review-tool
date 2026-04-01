import { PostHog } from 'posthog-node';
import { SrtLogger } from '../logging/srt-logger.js';

export interface AssessmentCompletedProperties {
    total_issues: number;
    new_issues: number;
    resolved_issues: number;
    reopened_issues: number;
    high_priority: number;
    medium_priority: number;
    low_priority: number;
    by_source: Record<string, number>;
}

export interface IssueProperties {
    check_id: string;
    description: string;
    priority: string;
    source: string;
    resource_type?: string;
}

export interface IssueResolvedProperties extends IssueProperties {
    days_open: number;
    assessments_open: number;
}

export interface IssueSuppressedProperties extends IssueProperties {
    days_open: number;
}

export interface IssueReopenedProperties extends IssueProperties {
    days_resolved: number;
}

export interface FixGeneratedProperties extends IssueProperties {
    model: string;
}

export interface StatusViewedProperties {
    open_issues: number;
    has_blocking: boolean;
}

export interface ConfigCompletedProperties {
    telemetry_enabled: boolean;
}

export interface UpdateCheckedProperties {
    current_version: string;
    update_available: boolean;
}

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

    public static captureAssessmentCompleted(properties: AssessmentCompletedProperties): void {
        PostHogClient.capture('assessment completed', { ...properties });
    }

    public static captureIssueDetected(properties: IssueProperties): void {
        PostHogClient.capture('issue detected', { ...properties });
    }

    public static captureIssueResolved(properties: IssueResolvedProperties): void {
        PostHogClient.capture('issue resolved', { ...properties });
    }

    public static captureIssueSuppressed(properties: IssueSuppressedProperties): void {
        PostHogClient.capture('issue suppressed', { ...properties });
    }

    public static captureIssueReopened(properties: IssueReopenedProperties): void {
        PostHogClient.capture('issue reopened', { ...properties });
    }

    public static captureFixGenerated(properties: FixGeneratedProperties): void {
        PostHogClient.capture('fix generated', { ...properties });
    }

    public static captureFixApplied(properties: IssueProperties): void {
        PostHogClient.capture('fix applied', { ...properties });
    }

    public static captureStatusViewed(properties: StatusViewedProperties): void {
        PostHogClient.capture('status viewed', { ...properties });
    }

    public static captureConfigCompleted(properties: ConfigCompletedProperties): void {
        PostHogClient.capture('config completed', { ...properties });
    }

    public static captureUpdateChecked(properties: UpdateCheckedProperties): void {
        PostHogClient.capture('update checked', { ...properties });
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
