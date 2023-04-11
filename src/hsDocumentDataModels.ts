/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Vishwas Anand Bhushan (Github @ vishwas1)
 */

export interface IEncryptedDoc {
  id?: string; //  MUST be a Base58-encoded 128-bit random value.
  sequence?: number; // MUST be an unsigned 64-bit number.
  jwe?: object; // JSON Web Encryption object, if decoded results in IStructredDoc
  data?: object; // Encrypted Data
  timestamp?: number;
}
