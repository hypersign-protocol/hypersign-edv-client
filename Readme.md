# Encrypted Data Vault

## Introduction

Encrypted Data Vault is a secure storage for your data. The digital data is encrypted and stored in a way that only owner of the data can access the data. In case any data breach happens the data is encrypted with owners public key (attached to a did) and only owner can decrypt the data with his private key.

## Data Vault

### Data Model

- Sequence - A unique counter for the data vault in order to ensure that clients are properly synchronized to the data vault. The value is required and MUST be an unsigned 64-bit number. (Incomplete Feature sync)
- controller - The DID of the controller of the data vault. The value is required and MUST be a valid DID.
- Invoker - The DID of the invoker of the data vault. The value is required and MUST be a valid DID. The root entities or cryptographic key(s) that are authorized to invoke an authorization capability to modify the data vault's configuration or read or write to it
- Delegator - The DID of the delegator of the data vault. The value is required and MUST be a valid DID.
- referenceId - Optional reference (application specific)
- keyAgreementKey.id - The DID of the key agreement key. The value is required and MUST be a valid DID.
- keyAgreementKey.type - The type of the key agreement key. The value is required and MUST be a valid type.
- hmac.id - The DID of the hmac key. The value is required and MUST be a valid DID.
- hmac.type - The type of the hmac key. The value is required and MUST be a valid type.

### Structred Document Format:

- content - The content of the data vault. The value is required and MUST be a valid JSON object.
  ```JSON
        {
            "content": {
                "key1": "value1",
                "key2": {
                    "key3": "value3"
                }
            }
        }
  ```

### Encrypted Document Format:

- id - Id of the encrypted document
- sequence - A unique counter for the data vault in order to ensure that clients are properly synchronized to the data vault. The value is required and MUST be an unsigned 64-bit number. (Incomplete Feature sync)
- jwe - The JWE of the encrypted document. The value is required and MUST be a valid JWE.
- encryptedData - The encrypted data of the encrypted document. (xpoly1305)
- indexed - The indexed data of the encrypted document. (ShaHmac256)
  ```JSON
  {
      "id":"z19x9iFMnfo4YLsShKAvnJk4L",
      "sequence":0,
      "indexed":[
          {
          "hmac":{
              "id":"did:ex:12345#key1",
              "type":"Sha256HmacKey2019"
          },
          "sequence":0,
          "attributes":[
          ]
          }
      ],
      "jwe":{
          "protected":"eyJlbmMiOiJDMjBQIn0",
          "recipients":[
          {
              "header":{
              "kid":"urn:123",
              "alg":"ECDH-ES+A256KW",
              "epk":{
                  "kty":"OKP",
                  "crv":"X25519",
                  "x":"d7rIddZWblHmCc0mYZJw39SGteink_afiLraUb-qwgs"
              },
              "apu":"d7rIddZWblHmCc0mYZJw39SGteink_afiLraUb-qwgs",
              "apv":"dXJuOjEyMw"
              },
              "encrypted_key":"4PQsjDGs8IE3YqgcoGfwPTuVG25MKjojx4HSZqcjfkhr0qhwqkpUUw"
          }
          ],
          "iv":"FoJ5uPIR6HDPFCtD",
          "ciphertext":"tIupQ-9MeYLdkAc1Us0Mdlp1kZ5Dbavq0No-eJ91cF0R0hE",
          "tag":"TMRcEPc74knOIbXhLDJA_w"
      }
  }
  ```

## Walkthrough : hypersign-edv-client

```sh
    npm  i https://github.com/hypersign-protocol/hid-ssi-js-sdk   --save
    npm i https://github.com/hypersign-protocol/hypersign-edv-client#dev-2.0

    npm i bip39 --save
    npm i @digitalbazaar/ed25519-verification-key-2020 --save
    npm i @digitalbazaar/x25519-key-agreement-key-2020 --save

```

#### For the specific premitivs

1.

- KeyType :
  - Ed25519VerificationKey2020
  - X25519KeyAgreementKey2020
  - Sha256HmacKey2019
- Encryption Algo :
  - AES-GCM-256 (JWE)

2. Create a new data vault

Pre-requisite :

````JS
    import * as bip39 from "bip39";
    import { Ed25519VerificationKey2020 } from "@digitalbazaar/ed25519-verification-key-2020";
    import { X25519KeyAgreementKey2020 } from "@digitalbazaar/x25519-key-agreement-key-2020";
    const hsDID = new HypersignDID({ namespace: 'testnet' });
    const seed = bip39.mnemonicToEntropy('rigid tribe noise city fashion industry amazing outside glue tide meadow draw option private north cheese winter exotic shop address million finish aunt ritual');
    const seedBuffer = Buffer.from(seed, 'hex')
    const keys = await hsDID.generateKeys({ seed: seedBuffer });
    const didDocument = await hsDID.generate({ publicKeyMultibase: keys.publicKeyMultibase })


    const keyResolver= async ({id})=>{
        // Resolve the key from the DID Document or from the blockchain or from any other source
        // sample authentication key after did resolution
        // Caution: This is just a sample snippet (This will cause error). You should resolve the key from the DID Document or from the blockchain or from any other source

    const authenticationKey = {
            '@context': 'https://w3id.org/security/suites/ed25519-2020/v1',
            id: didDocument.id.split('#')[0] + '#' + keys.publicKeyMultibase,
            controller: didDocument.id,
            publicKeyMultibase: keys.publicKeyMultibase,
        }
    const ed25519=await Ed25519VerificationKey2020.from(authenticationKey);
    return ed25519;

    }

    const authenticationKey = {
        '@context': 'https://w3id.org/security/suites/ed25519-2020/v1',
        id: didDocument.id.split('#')[0] + '#' + keys.publicKeyMultibase,
        controller: didDocument.id,
        publicKeyMultibase: keys.publicKeyMultibase,
        privateKeyMultibase: keys.privateKeyMultibase
    }
    const ed25519=await Ed25519VerificationKey2020.from(authenticationKey);
    const x25519=await X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({
        keyPair: {
            publicKeyMultibase: keys.publicKeyMultibase,
            privateKeyMultibase: keys.privateKeyMultibase
        }
    });

    const keyAgreementKey={
        id: didDocument.id.split('#')[0] + '#' + x25519.publicKeyMultibase,
        type: 'X25519KeyAgreementKey2020',

    }

    ```


Import the edv client class

   ```JS
import { HypersignEdvClientEd25519VerificationKey2020 } from "@hypersign-protocol/hypersign-vault-client";
  const vault=new HypersignEdvClientEd25519VerificationKey2020({
        keyResolver,
        url:'https://stage.hypermine.in/vault',
        ed25519VerificationKey2020:ed25519,
        x25519KeyAgreementKey2020:x25519,

    })
   const config={
        url:'https://stage.hypermine.in/vault',
        keyAgreementKey,
        controller: authenticationKey.id,
        edvId: 'urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66',

    }
    // Create and register a new data vault
    const res=await vault.registerEdv(config);


````

---

import the function to create a new data vault

```JS
import { HypersignEdvClient } from "@hypersign-protocol/hypersign-vault-client";
const config={
        url:'https://stage.hypermine.in/vault',
        keyAgreementKey,
        controller: authenticationKey.id,
        edvId: 'urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66',

    }

// this function will create a object of by calling HypersignEdvClientEd25519VerificationKey2020 constructor and return the object
const vault = HypersignEdvClient({
        keyResolver: dummy,
        url: 'https://stage.hypermine.in/vault/',
        invocationKeyPair: ed25519obj,
        keyagreementKeyPair: x25519,
})

// Create and register a new data vault
const res=vault.registerEdv(config)

```

3. Insert a document in the vault

   ```JS
   // document to be inserted
     const data = {
       content:{
       "@context": [
           "https://www.w3.org/2018/credentials/v1",
           "https://w3id.org/security/suites/ed25519-2020/v1"
       ],
       "id": "http://example.edu/credentials/1872",
       "type": ["VerifiableCredential"],
       "issuer": "did:hid:testnet:z7hzKZfBMt9WCo84ZN9G42kKUqx6TrGB862dvtLVENVr5",
       "issuanceDate": "2020-03-10T04:24:12.164Z",
       "credentialSubject": {
           "id": "did:hid:testnet:z7hzKZfBMt9WCo84ZN9G42kKUqx6TrGB862dvtLVENVr5",
           "degree": {
               "type": "BachelorDegree",
               "name": "Bachelor of Science and Arts"
           },
           "name": "Jayden Doe",
           "spouse": "did:hid:testnet:z7hzKZfBMt9WCo84ZN9G42kKUqx6TrGB862dvtLVENVr5"
       },
       "proof": {
           "type": "Ed25519Signature2020",
           "created": "2020-03-10T04:24:12.164Z",
           "verificationMethod": "did:hid:testnet:z7hzKZfBMt9WCo84ZN9G42kKUqx6TrGB862dvtLVENVr5#z7hzKZfBMt9WCo84ZN9G42kKUqx6TrGB862dvtLVENVr5",
           "proofPurpose": "assertionMethod",
           "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2..."
           }
       }
   }
   ```

   ```JS
   const res=await vault.insertDoc({
       document:data,
       edvId: 'urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66',
       recipents:[
           {
           id:didDocument.id.split('#')[0] + '#' + x25519.publicKeyMultibase
           type:'X25519KeyAgreementKey2020',
           publicKeyMultibase:x25519.publicKeyMultibase
           }
       ],
       // create index for the document to be inserted (for search purpose)
        indexs:     [{
           index:'content.id',
           unique:true
           },
           {
           index:'content.issuer',
           unique:false
           }.{
           index:'content.credentialSubject.id',
           unique:false
           }]

   })

   ```

4. Fetch the document from the vault
   ```JS
   const res=await vault.fetchDoc({
       edvId: 'urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66',
       docId:'${documentId}'
   })
   ```
5. Query the vault

   ```JS
   const res=await vault.query({
       edvId: 'urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66',
     equals:[
          { 'content.credentialSubject.id':'did:hid:testnet:z7hzKZfBMt9WCo84ZN9G42kKUqx6TrGB862dvtLVENVr5'
       }]
   })
   ```

6. Update the document in the vault

   ```JS
   const res=await vault.updateDoc({
       edvId: 'urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66',
       docId:'${documentId}',
       document:{
           content:{
               // new data object
               "@context": [
                   "https://www.w3.org/2018/credentials/v1",
                   "https://w3id.org/security/suites/ed25519-2020/v1"
               ],
               "id": "http://example.edu/credentials/1872",
               "type": ["VerifiableCredential"],
               "issuer": "did:hid:testnet:z7hzKZfBMt9WCo84ZN9G42kKUqx6TrGB862dvtLVENVr5",
               "issuanceDate": "2020-03-10T04:24:12.164Z",
               "credentialSubject": {
                   "id": "did:hid:testnet:z7hzKZfBMt9WCo84ZN9G42kKUqx6TrGB862dvtLVENVr5",
                   "degree": {
                       "type": "BachelorDegree",
                       "name": "Bachelor of Science and Arts"
                   },
                   "name": "Jayden Doe",
                   "spouse": "did:hid:testnet:z7hzKZfBMt9WCo84ZN9G42kKUqx6TrGB862dvtLVENVr5"
               },
               "proof": {
                   "type": "Ed25519Signature2020",
                   "created": "2020-03-10T04:24:12.164Z",
                   "verificationMethod": "did:hid:testnet:z7hzKZfBMt9WCo84ZN9G42kKUqx6TrGB862dvtLVENVr5#z7hzKZfBMt9WCo84ZN9G42kKUqx6TrGB862dvtLVENVr5",
                   "proofPurpose": "assertionMethod",
                   "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2..."
                   }
               }
       }
       ,
       indexs:     [{
           index:'content.id',
           unique:true
           },
           {
           index:'content.issuer',
           unique:false
           }.{
           index:'content.credentialSubject.id',
           unique:false
           }]
   })

   ```

7. Decrypt the document in the vault
   ```JS
   const res=await vault.hsCipher.decryptDoc({
       jwe: document.jwe,
       keyAgreementKey: x25519
       })
   ```

---

#### For Specific Crypto Premitves

1.

- KeyType :
  - EcdsaSecp256k1RecoveryMethod2020
  - X25519KeyAgreementKeyEIP5630
  - Sha256HmacKey2019
- Encryption Algo :
  - x25519-xsalsa20-poly1305 (encrypted using X25519KeyAgreementKeyEIP5630)

2. Create a new data vault
   Pre-requisite :

   ```js
   import multibase from 'multibase';
   function base64toMultibase58(base64) {
     const arr = Buffer.from(base64, 'base64');
     const base58 = multibase.encode('base58btc', arr);
     return Buffer.from(base58).toString();
   }
   const account = await ethereum.request({ method: 'eth_requestAccounts' });
   const publicKey = await ethereum.request({ method: 'eth_getEncryptionPublicKey', params: [account[0]] });
   const url = 'https://stage.hypermine.in/vault';
   const did = `did:hid:testnet:${account[0]}`;
   const verificationMethod = {
     id: did + '#' + `eip155:1:${account[0]}`,
     type: 'EcdsaSecp256k1RecoveryMethod2020',
     controller: did,
     blockchainAccountId: `eip155:1:${account[0]}`,
   };

   const publicKeyMultibase = base64toMultibase58(publicKey);
   const keyAgreementKeyPair = {
     id: did + '#' + publicKeyMultibase,
     type: 'X25519KeyAgreementKeyEIP5630',
     controller: did,
     publicKeyMultibase,
   };
   ```

   Import the edv client class and create a new vault

   ```js
   import { HypersignEdvClientEcdsaSecp256k1 } from '@hypersign-protocol/hypersign-vault-client';

   const vault = new HypersignEdvClientEcdsaSecp256k1({
     url,
     keyAgreement: keyAgreementKeyPair,
     verificationMethod,
   });
   const config = {
     edvId: 'urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66',
     verificationMethod,
     keyAgreement: keyAgreementKeyPair,
   };
   const res = await vault.registerEdv(config);
   ```

   import the function to create a new data vault

   ```js
   import { HypersignEdvClient } from '@hypersign-protocol/hypersign-vault-client';
   const config = {
     edvId: 'urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66',
     verificationMethod,
     keyAgreement: keyAgreementKeyPair,
   };

   const vault = HyperSignEdvClient({
     url,
     invocationKeyPair: verificationMethod,
     keyagreementKeyPair: keyAgreementKeyPair,
   });

   const res = await vault.registerEdv(config);
   ```

3. Insert Document

   ```JS
         const res=await vault.insertDoc({
       document:data,
       edvId: 'urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a88',
       recipients: [{
           id:didDocument.id.split('#')[0] + '#' + x25519.publicKeyMultibase
           type:'X25519KeyAgreementKey2020',
           }],
       indexs:[{
               index:'content.id',
               unique:true

           },
           {
               index:'content.credentialSubject.id',
               unique:false

           },{
               index:'content.credentialSubject.degree.type',
               unique:false
           },{
               index:'content.credentialSubject.degree.name',
               unique:false

           },
           {
               index:'content.credentialSubject.name',
               unique:false
           },
           {
               index:'content.credentialSubject.spouse',
               unique:false
           }

           ],
       })
   ```

4. Decrypt the document in the vault:

```JS
  const doc= await vault.decryptDocument(
    {
        encryptedDocument:res.document.encryptedData,
        recipient:{
            id: keyAgreementKeyPair.id,
            type: 'X25519KeyAgreementKeyEIP5630'
        }

    })
```

---

## Specs :

- Authorization Strategies : HTTP Signatures (https://tools.ietf.org/html/draft-cavage-http-signatures-12)
- Protocol/API : HTTP 1.1 / APIs
- Encryption Strategies : AES-GCM , XSalsa20Poly1305
- Versioning Strategies and Replication Strategies : TODO
- Notification mechanisms - TODO

## Indexing Strategies :

- Hmac Blinding : This is a technique to index the data without revealing the data. This is done by using a secret key to generate a HMAC of the data and then using the HMAC as the index. This way the data is not revealed but can be searched. [More](https://identity.foundation/edv-spec/#creating-encrypted-indexes)

### References :

- [EDV Spec](https://identity.foundation/edv-spec/)
