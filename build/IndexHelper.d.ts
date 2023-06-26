export declare class IndexHelper {
    /**
     * Creates a new IndexHelper instance that can be used to blind EDV
     * document attributes to enable indexing.
     *
     * @returns {IndexHelper}.
     */
    private indexes;
    private compoundIndexes;
    private _cache;
    constructor();
    /**
     * Ensures that future documents inserted or updated using this client
     * instance will be indexed according to the given attribute, provided that
     * they contain that attribute. Compound indexes can be specified by
     * providing an array for `attribute`.
     *
     * Queries may be performed using compound indexes without specifying all
     * attributes in the compound index so long as there is at least one value
     * (or the attribute name for "has" queries) specified for consecutive
     * attributes starting with the first. This allows for querying using only
     * a prefix of a compound index. However, uniqueness will not be enforced
     * unless all attributes in the compound index are present in a document.
     *
     * @param {object} options - The options to use.
     * @param {string|string[]} options.attribute - The attribute name or an
     *   array of attribute names to create a unique compound index.
     * @param {boolean} [options.unique=false] - Set to `true` if the index
     *   should be considered unique, `false` if not.
     * @param {object} [options.hmac] - An optional HMAC API with `id`, `sign`,
     *   and `verify` properties for prewarming caches.
     */
    ensureIndex({ attribute, hmac, unique }: {
        attribute: any;
        hmac: any;
        unique?: boolean | undefined;
    }): void;
    createEntry({ hmac, doc }: {
        hmac: any;
        doc: any;
    }): Promise<{
        hmac: {
            id: any;
            type: any;
        };
        sequence: any;
        attributes: {
            name: any;
            value: any;
            unique: boolean;
        }[];
    }>;
    _buildBlindAttributes({ hmac, doc, equal, has }: {
        hmac?: any;
        doc?: any;
        equal?: any;
        has?: any;
    }): Promise<{
        name: any;
        value: any;
        unique: boolean;
    }[]>;
    updateEntry({ hmac, doc }: {
        hmac: any;
        doc: any;
    }): Promise<any>;
    _hashAttribute({ name, value }: {
        name: any;
        value: any;
    }): Promise<{
        name: Uint8Array;
        value: Uint8Array;
    }>;
    buildQuery({ hmac, equals, has }: {
        hmac: any;
        equals: any;
        has: any;
    }): Promise<{
        index: any;
        equals: any[];
        has: any[];
    }>;
    _blindHashedAttribute({ hmac, hashedAttribute }: {
        hmac: any;
        hashedAttribute: any;
    }): Promise<{
        name: any;
        value: any;
        unique: boolean;
    }>;
    _hashCompoundAttribute({ hashedAttributes, length }: {
        hashedAttributes: any;
        length?: any;
    }): Promise<{
        name: Uint8Array;
        value: Uint8Array;
    }>;
    _blindData(hmac: any, data: any): Promise<any>;
    _getMatchingIndexes({ doc, equal, has }: {
        doc: any;
        equal: any;
        has: any;
    }): {
        attributeValues: Map<any, any>;
        simpleMatches: {
            attribute: any;
            unique: boolean;
        }[];
        compoundMatches: {
            attributes: string[];
            unique: boolean;
        }[];
    };
    _matchIndexes({ matchFn }: {
        matchFn: any;
    }): {
        simpleMatches: {
            attribute: any;
            unique: boolean;
        }[];
        compoundMatches: {
            attributes: string[];
            unique: boolean;
        }[];
    };
    _matchDocument({ attribute, attributeValues, doc }: {
        attribute: any;
        attributeValues: any;
        doc: any;
    }): boolean;
    _prewarmCache({ attributes, hmac }: {
        attributes: any;
        hmac: any;
    }): Promise<any[]>;
    _cachedHmac({ hmac, data }: {
        hmac: any;
        data: any;
    }): any;
    _dereferenceAttribute({ attribute, keys, doc }: {
        attribute?: any;
        keys?: any;
        doc?: any;
    }): any;
    _parseAttribute(attribute: any): string[];
}
//# sourceMappingURL=IndexHelper.d.ts.map