export enum CommentFormat {
    BLOCK = 'BLOCK',
    HASH = 'HASH',
    HTML = 'HTML',
    LINE = 'LINE'
}

export enum ComplianceStatus {
    COMPLETE = 'COMPLETE',
    SKIPPED = 'SKIPPED'
}

export interface License {
    readonly name: string;
    readonly licenseContent: string;
    readonly headerContent: string;
    readonly noticeContent: string;
}

export class SourceFile {
    public constructor(
        public readonly path: string,
        public readonly extension: string,
        public readonly content: string
    ) {}

    public hasShebang(): boolean {
        return this.content.startsWith('#!');
    }

    public getShebang(): string | null {
        if (!this.hasShebang()) {
            return null;
        }
        const firstLineEnd = this.content.indexOf('\n');
        return firstLineEnd === -1 ? this.content : this.content.substring(0, firstLineEnd + 1);
    }
}

export class Header {
    public constructor(public readonly content: string) {}
}

export interface FileComplianceResult {
    file: SourceFile;
    hasHeader: boolean;
    isValid: boolean;
}
