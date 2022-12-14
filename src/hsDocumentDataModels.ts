export interface IEncryptedDoc {
  id?: string; //  MUST be a Base58-encoded 128-bit random value.
  sequence?: number; // MUST be an unsigned 64-bit number.
  jwe: object; // JSON Web Encryption object, if decoded results in IStructredDoc
  timestamp?: number;
}
