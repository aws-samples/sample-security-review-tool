import { CommentFormat, License } from './types.js';

interface CommentStyle {
    start?: string;
    line: string;
    end?: string;
}

export class HeaderFormatter {
    private readonly commentStyles: Map<CommentFormat, CommentStyle> = new Map([
        [CommentFormat.BLOCK, { start: '/*', line: ' * ', end: ' */' }],
        [CommentFormat.HASH, { line: '# ' }],
        [CommentFormat.HTML, { start: '<!--', line: ' ', end: '-->' }],
        [CommentFormat.LINE, { line: '// ' }]
    ]);

    public format(license: License, commentFormat: CommentFormat): string {
        const style = this.commentStyles.get(commentFormat);
        if (!style) {
            throw new Error(`Unsupported comment format: ${commentFormat}`);
        }

        const lines = license.headerContent.split('\n');
        let formattedHeader = style.start ? `${style.start}\n` : '';

        for (const line of lines) {
            formattedHeader += `${style.line}${line}\n`;
        }

        if (style.end) {
            formattedHeader += style.end;
        }

        return formattedHeader;
    }

    public insertIntoFile(fileContent: string, formattedHeader: string): string {
        const hasShebang = fileContent.trimStart().startsWith('#!');

        if (hasShebang) {
            const lines = fileContent.split('\n');
            const shebangLine = lines[0];
            const remainingContent = lines.slice(1).join('\n');
            return `${shebangLine}\n${formattedHeader}\n${remainingContent}`;
        }

        return `${formattedHeader}\n${fileContent}`;
    }
}
