// Type definitions for [~THE LIBRARY NAME~] [~OPTIONAL VERSION NUMBER~]
// Project: [~THE PROJECT NAME~]
// Definitions by: [~YOUR NAME~] <[~A URL FOR YOU~]>

interface GpgKeyInfo {
  type: string;
  capabilities: string;
  fingerprint: string;
  keygrip: string;
  userId?: string;
}

interface IdentityRecord {
  IdentityRecordType?: string;
  fieldIdentityID?: number;
  fieldIdentityStatus?: string;
  fieldIdentityComment?: string;
  fieldIdentityCreated?: string;
  fieldIdentityRest?: string;
}

/**
 * Cnfiguration values for the `gpgIndicator.binaryHost option`.
 */
type binaryHostConfig = "linux" | "windows";
