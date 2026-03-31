import { Header, License } from './types.js';

interface CommentFormatDetection {
    start?: string;
    line: string;
    end?: string;
}

export class HeaderDetector {
    public normalizeHeader(header: Header): string {
        const rawText = header.content;
        const commentFormat = this.detectCommentFormat(rawText);

        if (!commentFormat) {
            return rawText.trim();
        }

        return this.stripCommentCharacters(rawText, commentFormat);
    }

    public isValidHeader(header: Header, validLicenses: License[]): boolean {
        const normalizedHeader = this.normalizeHeader(header);
        return validLicenses.some(license => normalizedHeader === license.headerContent);
    }

    public detectHeader(fileContent: string): Header | null {
        const contentAfterShebang = this.skipShebang(fileContent);
        const commentFormat = this.detectCommentFormat(contentAfterShebang);

        if (!commentFormat) {
            return null;
        }

        const headerRegex = this.buildHeaderRegex(commentFormat);
        const match = contentAfterShebang.match(headerRegex);

        if (match && this.containsCopyright(match[0])) {
            return new Header(match[0]);
        }

        return null;
    }

    public removeHeader(fileContent: string): string {
        const hasShebang = fileContent.startsWith('#!');
        let shebangLine = '';

        if (hasShebang) {
            const firstNewline = fileContent.indexOf('\n');
            shebangLine = firstNewline !== -1 ? fileContent.substring(0, firstNewline + 1) : fileContent;
        }

        const contentAfterShebang = this.skipShebang(fileContent);
        const commentFormat = this.detectCommentFormat(contentAfterShebang);

        if (!commentFormat) {
            return fileContent;
        }

        const headerRegex = this.buildHeaderRegex(commentFormat);
        const updatedContent = contentAfterShebang.replace(headerRegex, '').trimStart();

        return hasShebang ? shebangLine + updatedContent : updatedContent;
    }

    public removeAllHeaders(fileContent: string): string {
        let result = fileContent;

        while (this.detectHeader(result) !== null) {
            result = this.removeHeader(result);
        }

        return result;
    }

    private skipShebang(content: string): string {
        if (content.startsWith('#!')) {
            const firstNewline = content.indexOf('\n');
            return firstNewline !== -1 ? content.substring(firstNewline + 1) : content;
        }
        return content;
    }

    private detectCommentFormat(content: string): CommentFormatDetection | null {
        const trimmedContent = content.trimStart();

        if (trimmedContent.startsWith('<!--')) {
            return { start: '<!--', line: '', end: '-->' };
        }

        if (trimmedContent.startsWith('/*')) {
            return { start: '/*', line: '', end: '*/' };
        }

        if (trimmedContent.startsWith('//')) {
            return { line: '//' };
        }

        if (trimmedContent.startsWith('#')) {
            return { line: '#' };
        }

        if (trimmedContent.startsWith('--')) {
            return { line: '--' };
        }

        return null;
    }

    private containsCopyright(text: string): boolean {
        return /copyright/i.test(text);
    }


    private buildHeaderRegex(format: CommentFormatDetection): RegExp {
        if (format.start && format.end) {
            const start = this.escapeForRegex(format.start);
            const end = this.escapeForRegex(format.end);

            // nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
            // — input is from internal comment format definitions, not user-controlled; escapeForRegex sanitizes special characters
            return new RegExp(`^\\s*${start}[\\s\\S]*?${end}`, 'm');
        } else {
            const linePrefix = this.escapeForRegex(format.line);
            return new RegExp(`^\\s*(${linePrefix}.*(?:\\r?\\n|$))+`, 'm');
        }
    }

    private escapeForRegex(text: string): string {
        return text.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
    }

    private stripCommentCharacters(text: string, format: CommentFormatDetection): string {
        if (format.start && format.end) {
            return text
                .replace(new RegExp(`^\\s*${this.escapeForRegex(format.start)}`), '')
                .replace(new RegExp(`${this.escapeForRegex(format.end)}\\s*$`), '')
                .split(/\r?\n/)
                .map(line => line.replace(/^\s*\*?\s?/, ''))
                .filter(line => line.length > 0)
                .join('\n');
        } else {
            return text
                .split(/\r?\n/)
                .map(line => line.replace(new RegExp(`^\\s*${this.escapeForRegex(format.line)}\\s?`), ''))
                .filter(line => line.length > 0)
                .join('\n');
        }
    }
}
