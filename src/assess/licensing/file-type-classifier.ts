import { CommentFormat } from './types.js';

export class FileTypeClassifier {
    private readonly extensionMap: Map<string, CommentFormat> = new Map([
        ['html', CommentFormat.HTML],
        ['xml', CommentFormat.HTML],
        ['svg', CommentFormat.HTML],
        ['py', CommentFormat.HASH],
        ['rb', CommentFormat.HASH],
        ['sh', CommentFormat.HASH],
        ['bash', CommentFormat.HASH],
        ['zsh', CommentFormat.HASH],
        ['ex', CommentFormat.HASH],
        ['exs', CommentFormat.HASH],
        ['yaml', CommentFormat.HASH],
        ['yml', CommentFormat.HASH],
        ['ts', CommentFormat.BLOCK],
        ['js', CommentFormat.BLOCK],
        ['java', CommentFormat.BLOCK],
        ['cs', CommentFormat.BLOCK],
        ['go', CommentFormat.BLOCK],
        ['php', CommentFormat.BLOCK],
        ['swift', CommentFormat.BLOCK],
        ['kt', CommentFormat.BLOCK],
        ['cpp', CommentFormat.BLOCK],
        ['c', CommentFormat.BLOCK],
        ['h', CommentFormat.BLOCK],
        ['hpp', CommentFormat.BLOCK],
        ['tsx', CommentFormat.BLOCK],
        ['jsx', CommentFormat.BLOCK],
        ['rs', CommentFormat.BLOCK],
        ['dart', CommentFormat.BLOCK],
        ['scala', CommentFormat.BLOCK],
        ['groovy', CommentFormat.BLOCK]
    ]);

    public classifyByExtension(extension: string): CommentFormat {
        const normalizedExtension = extension.toLowerCase().replace(/^\./, '');
        return this.extensionMap.get(normalizedExtension) || CommentFormat.BLOCK;
    }

    public getSupportedExtensions(): string[] {
        return Array.from(this.extensionMap.keys());
    }
}
