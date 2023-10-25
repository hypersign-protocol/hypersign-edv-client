export declare const authenticationKey: {
    '@context': string;
    id: string;
    controller: string;
    type: string;
    publicKeyMultibase: string;
    privateKeyMultibase: string;
};
export declare function Ed25519Keypair(key?: {
    '@context': string;
    id: string;
    controller: string;
    type: string;
    publicKeyMultibase: string;
    privateKeyMultibase: string;
}): Promise<Ed25519VerificationKey2020>;
export declare function X25519KeyAgreementKeyPair(key?: {
    '@context': string;
    id: string;
    controller: string;
    type: string;
    publicKeyMultibase: string;
    privateKeyMultibase: string;
}): Promise<any>;
export declare const hypersignDIDKeyResolverForEd25519KeyPair: ({ id }: {
    id: any;
}) => Promise<Ed25519VerificationKey2020>;
export declare const hypersignDIDKeyResolverForX25519KeyPair: ({ id }: {
    id: any;
}) => Promise<any>;
//# sourceMappingURL=key.spec.d.ts.map