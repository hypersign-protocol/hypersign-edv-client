declare namespace _default {
  namespace jwe {
    const _protected: string;
    export { _protected as protected };
    export const recipients: {
      header: {
        kid: string;
        alg: string;
        epk: {
          kty: string;
          crv: string;
          x: string;
        };
        apu: string;
        apv: string;
      };
      encrypted_key: string;
    }[];
    export const iv: string;
    export const ciphertext: string;
    export const tag: string;
  }
}
export default _default;
//# sourceMappingURL=message.d.ts.map
