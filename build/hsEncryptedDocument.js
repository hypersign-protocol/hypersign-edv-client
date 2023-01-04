"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var HypersignEncryptedDocument = /** @class */ (function () {
    function HypersignEncryptedDocument(_a) {
        var jwe = _a.jwe;
        this.encDoc = {
            jwe: jwe,
            id: '',
            sequence: 0,
            timestamp: 0,
        };
    }
    HypersignEncryptedDocument.prototype.get = function () {
        return this.encDoc;
    };
    return HypersignEncryptedDocument;
}());
exports.default = HypersignEncryptedDocument;
