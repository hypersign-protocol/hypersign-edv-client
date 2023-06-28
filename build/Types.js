"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.WalletTypes = exports.HmacKeyTypes = exports.VerificationKeyTypes = exports.KeyAgreementKeyTypes = void 0;
var KeyAgreementKeyTypes;
(function (KeyAgreementKeyTypes) {
    KeyAgreementKeyTypes["X25519KeyAgreementKey2020"] = "X25519KeyAgreementKey2020";
    KeyAgreementKeyTypes["X25519KeyAgreementKeyEIP5630"] = "X25519KeyAgreementKeyEIP5630";
})(KeyAgreementKeyTypes = exports.KeyAgreementKeyTypes || (exports.KeyAgreementKeyTypes = {}));
var VerificationKeyTypes;
(function (VerificationKeyTypes) {
    VerificationKeyTypes["Ed25519VerificationKey2020"] = "Ed25519VerificationKey2020";
    VerificationKeyTypes["EcdsaSecp256k1VerificationKey2019"] = "EcdsaSecp256k1VerificationKey2019";
    VerificationKeyTypes["EcdsaSecp256k1RecoveryMethod2020"] = "EcdsaSecp256k1RecoveryMethod2020";
})(VerificationKeyTypes = exports.VerificationKeyTypes || (exports.VerificationKeyTypes = {}));
var HmacKeyTypes;
(function (HmacKeyTypes) {
    HmacKeyTypes["Sha256HmacKey2020"] = "Sha256HmacKey2020";
})(HmacKeyTypes = exports.HmacKeyTypes || (exports.HmacKeyTypes = {}));
var WalletTypes;
(function (WalletTypes) {
    WalletTypes["Metamask"] = "metamask";
    WalletTypes["Keplr"] = "keplr";
})(WalletTypes = exports.WalletTypes || (exports.WalletTypes = {}));
