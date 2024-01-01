
interface GpgKeyInfo {
  type: string;
  capabilities: string;
  fingerprint: string;
  keygrip: string;
  userId?: string;
}
