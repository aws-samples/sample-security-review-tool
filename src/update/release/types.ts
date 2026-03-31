export const PLATFORM_BINARIES = {
    'darwin-arm64': 'srt-cli-v{version}-macos-arm64.tar.gz',
    'darwin-x64': 'srt-cli-v{version}-macos-x64.tar.gz',
    'linux-x64': 'srt-cli-v{version}-linux-x64.tar.gz',
    'linux-arm64': 'srt-cli-v{version}-linux-arm64.tar.gz',
    'win32-x64': 'srt-cli-v{version}-windows-x64.zip'
} as const;

export type PlatformKey = keyof typeof PLATFORM_BINARIES;

export interface ReleaseInfo {
    version: string;
    downloadUrl: string;
}

export type ReleaseCheckResult =
    | { status: 'update_available'; releaseInfo: ReleaseInfo }
    | { status: 'up_to_date' };
