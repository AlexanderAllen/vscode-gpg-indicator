
interface GpgKeyInfo {
  type: string;
  capabilities: string;
  fingerprint: string;
  keygrip: string;
  userId?: string;
}

export interface IdentityRecord {
  IdentityRecordType?: string;
  fieldIdentityID?: number;
  fieldIdentityStatus?: string;
  fieldIdentityComment?: string;
  fieldIdentityCreated?: string;
  fieldIdentityRest?: string;
}

interface KeyRecord {
  KeyRecordType: string;
  fieldKeyType: string;
  fieldKeyStatus: string;
  fieldLength: string;
  fieldPubKeyAlgo: string;
  fieldKeyID: string;
  fieldCreated: string;
  fieldExpires: string;
  fieldTrust: string;
  fieldOwnerTrust: string;
  fieldUserID: string;
  fieldSigClass: string;
  fieldCapability: string;
  fieldCurveName: string;
  fieldRest: string;

  FingerprintRecordType: string;
  fingerprint: string;

  GripRecordType: string;
  grip: string;

  IdentityRecordType: string;
  fieldIdentityStatus: string;
  fieldIdentityCreated: string;
  fieldIdentityID: string;
  fieldIdentityComment: string;
  fieldIdentityRest: string;
}
