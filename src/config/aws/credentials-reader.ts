import fs from 'fs/promises';
import path from 'path';
import os from 'os';
import { AwsProfile } from './types.js';

export class AwsCredentialsFileReader {
  private static readonly CREDENTIALS_FILE_PATHS = [
    path.join(os.homedir(), '.aws', 'credentials'),
    path.join(os.homedir(), '.aws', 'config')
  ];

  async discoverProfiles(): Promise<AwsProfile[]> {
    const profilesMap = new Map<string, AwsProfile>();
    let hasDefaultProfile = false;

    for (const filePath of AwsCredentialsFileReader.CREDENTIALS_FILE_PATHS) {
      try {
        const content = await fs.readFile(filePath, 'utf8');
        const foundProfiles = this.parseAwsConfigFile(content);

        foundProfiles.forEach(profile => {
          const existing = profilesMap.get(profile.name);
          if (existing) {
            profilesMap.set(profile.name, {
              ...existing,
              region: profile.region || existing.region,
              isDefault: existing.isDefault || profile.isDefault
            });
          } else {
            profilesMap.set(profile.name, profile);
          }
          if (profile.isDefault) {
            hasDefaultProfile = true;
          }
        });
      } catch (error) {
        continue;
      }
    }

    const profileArray: AwsProfile[] = Array.from(profilesMap.values());

    // If no explicit default profile found but we have profiles, mark the first as default
    if (!hasDefaultProfile && profileArray.length > 0 && !profileArray.find(p => p.name === 'default')) {
      profileArray[0].isDefault = true;
    }

    return profileArray.sort((a, b) => {
      if (a.isDefault) return -1;
      if (b.isDefault) return 1;

      return a.name.localeCompare(b.name);
    });
  }

  private parseAwsConfigFile(content: string): AwsProfile[] {
    const profiles: AwsProfile[] = [];
    const lines = content.split('\n');
    let currentProfile: AwsProfile | null = null;

    for (const line of lines) {
      const trimmedLine = line.trim();

      // Look for profile sections like [default], [profile profile-name], or [profile-name]
      if (trimmedLine.startsWith('[') && trimmedLine.endsWith(']')) {
        // Save the previous profile before starting a new one
        if (currentProfile) {
          profiles.push(currentProfile);
        }

        const sectionName = trimmedLine.slice(1, -1);

        if (sectionName === 'default') {
          currentProfile = { name: 'default', isDefault: true, region: 'us-east-1' };
        } else if (sectionName.startsWith('profile ')) {
          // Handle [profile profile-name] format (from ~/.aws/config)
          const profileName = sectionName.substring(8); // Remove 'profile ' prefix
          currentProfile = { name: profileName, isDefault: false, region: 'us-east-1' };
        } else if (sectionName.length > 0 && !sectionName.includes(' ')) {
          // Handle [profile-name] format (from ~/.aws/credentials)
          // Only accept single-word section names to avoid parsing non-profile sections
          currentProfile = { name: sectionName, isDefault: false, region: 'us-east-1' };
        } else {
          currentProfile = null;
        }
      } else if (currentProfile && trimmedLine.includes('=')) {
        const [key, ...valueParts] = trimmedLine.split('=');
        const value = valueParts.join('=').trim();

        if (key.trim() === 'region') {
          currentProfile.region = value;
        }
      }
    }

    // Add last profile
    if (currentProfile) {
      profiles.push(currentProfile);
    }

    return profiles;
  }
}
