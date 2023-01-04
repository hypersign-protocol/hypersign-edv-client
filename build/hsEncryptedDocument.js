"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var HypersignEncryptedDocument = /** @class */ (function () {
    function HypersignEncryptedDocument(_a) {
        var jwe = _a.jwe, id = _a.id, sequence = _a.sequence;
        this.encDoc = {
            jwe: jwe,
            id: id,
            sequence: sequence,
            timestamp: 0,
        };
    }
    HypersignEncryptedDocument.prototype.get = function () {
        return this.encDoc;
    };
    return HypersignEncryptedDocument;
}());
exports.default = HypersignEncryptedDocument;
