"use strict";
/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Vishwas Anand Bhushan (Github @ vishwas1)
 */
Object.defineProperty(exports, "__esModule", { value: true });
var HypersignEncryptedDocument = /** @class */ (function () {
    function HypersignEncryptedDocument(_a) {
        var data = _a.data, jwe = _a.jwe, id = _a.id, sequence = _a.sequence;
        this.encDoc = {
            jwe: jwe ? jwe : undefined,
            data: data ? data : undefined,
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
