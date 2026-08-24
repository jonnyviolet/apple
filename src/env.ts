export interface Env {
  DB: D1Database;

  PASS_TYPE_IDENTIFIER: string;
  TEAM_IDENTIFIER: string;
  WEB_SERVICE_URL: string;
  APNS_HOST: string;
  /** Serial of the single pass distributed through Apple Messages for Business. */
  SHARED_SERIAL_NUMBER: string;

  PASS_CERT_P12_BASE64: string;
  PASS_CERT_P12_PASSWORD: string;
  WWDR_CERT_PEM: string;

  APNS_KEY_P8: string;
  APNS_KEY_ID: string;

  ADMIN_TOKEN: string;
}

export interface PassRecord {
  serial_number: string;
  authentication_token: string;
  overrides: string;
  updated_at: number;
  created_at: number;
  voided: number;
}

export interface RegistrationRecord {
  device_library_identifier: string;
  serial_number: string;
  push_token: string;
  created_at: number;
}
