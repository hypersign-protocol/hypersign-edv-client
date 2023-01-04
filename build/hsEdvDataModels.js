"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.HmacKeyTypes = exports.VerificationKeyTypes = exports.KeyAgreementKeyTypes = void 0;
var KeyAgreementKeyTypes;
(function (KeyAgreementKeyTypes) {
    KeyAgreementKeyTypes["X25519KeyAgreementKey2020"] = "X25519KeyAgreementKey2020";
})(KeyAgreementKeyTypes = exports.KeyAgreementKeyTypes || (exports.KeyAgreementKeyTypes = {}));
var VerificationKeyTypes;
(function (VerificationKeyTypes) {
    VerificationKeyTypes["Ed25519VerificationKey2020"] = "Ed25519VerificationKey2020";
})(VerificationKeyTypes = exports.VerificationKeyTypes || (exports.VerificationKeyTypes = {}));
var HmacKeyTypes;
(function (HmacKeyTypes) {
    HmacKeyTypes["Sha256HmacKey2020"] = "Sha256HmacKey2020";
})(HmacKeyTypes = exports.HmacKeyTypes || (exports.HmacKeyTypes = {}));
