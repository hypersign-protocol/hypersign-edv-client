export var KeyAgreementKeyTypes;
(function (KeyAgreementKeyTypes) {
    KeyAgreementKeyTypes["X25519KeyAgreementKey2020"] = "X25519KeyAgreementKey2020";
    KeyAgreementKeyTypes["X25519KeyAgreementKeyEIP5630"] = "X25519KeyAgreementKeyEIP5630";
})(KeyAgreementKeyTypes || (KeyAgreementKeyTypes = {}));
export var VerificationKeyTypes;
(function (VerificationKeyTypes) {
    VerificationKeyTypes["Ed25519VerificationKey2020"] = "Ed25519VerificationKey2020";
    VerificationKeyTypes["EcdsaSecp256k1VerificationKey2019"] = "EcdsaSecp256k1VerificationKey2019";
    VerificationKeyTypes["EcdsaSecp256k1RecoveryMethod2020"] = "EcdsaSecp256k1RecoveryMethod2020";
})(VerificationKeyTypes || (VerificationKeyTypes = {}));
export var HmacKeyTypes;
(function (HmacKeyTypes) {
    HmacKeyTypes["Sha256HmacKey2020"] = "Sha256HmacKey2020";
})(HmacKeyTypes || (HmacKeyTypes = {}));
export var WalletTypes;
(function (WalletTypes) {
    WalletTypes["Metamask"] = "metamask";
    WalletTypes["Keplr"] = "keplr";
})(WalletTypes || (WalletTypes = {}));
