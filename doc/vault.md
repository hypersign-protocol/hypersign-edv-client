# Tutorial: Hypersign DataVault

## Hypersign DataVault currently supports two key Types :

    1. Ed25519VerificationKey2020 and X25519KeyAgreementKey2020
    2. EcdsaSecp256k1RecoveryMethod2020 and X25519KeyAgreementKeyEIP5630

## Hypersign DataVault currently supports two encryption algorithms :

    1. x25519-xsalsa20-poly1305
    2. AES-GCM   (JWE)

## Example Flow with Type 1 keys and AES-GCM encryption

### Type 1: Ed25519VerificationKey2020 and AES-GCM

```bash
    npm  i https://github.com/hypersign-protocol/hid-ssi-js-sdk   --save
    npm i https://github.com/hypersign-protocol/hypersign-edv-client#dev-2.0

    npm i bip39 --save
    npm i @digitalbazaar/ed25519-verification-key-2020 --save
    npm i @digitalbazaar/x25519-key-agreement-key-2020 --save
```

```javascript

    import { HypersignEdvClientEd25519VerificationKey2020 } from "@hypersign-protocol/hypersign-vault-client";
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


    const res=await vault.registerEdv(config);
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
    }}

    const res1=await vault.insertDoc({
        document:data,
        edvId: 'urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66',
        recipients: [{
            id:didDocument.id.split('#')[0] + '#' + x25519.publicKeyMultibase
            type:'X25519KeyAgreementKey2020',
            publicKeyMultibase:x25519.publicKeyMultibase
            }],
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

    const res2= await client.fetchDoc({
        edvId: 'urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66',
        documentId: res1.document.id,
    })

    // Decrypt the fetched document
    const decryptdDocument= await vault.hsCipher.decryptObject({
        jwe:res2.document.jwe,
        keyAgreementKey:x25519,
    })

    const query=await vault.Query({
        edvId: 'urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66',
        equals:[
           { 'content.credentialSubject.id':'did:hid:testnet:z7hzKZfBMt9WCo84ZN9G42kKUqx6TrGB862dvtLVENVr5'
        }]
    })





```

## Example Flow with Type 2 keys and x25519-xsalsa20-poly1305 encryption

### Type 2: EcdsaSecp256k1RecoveryMethod2020 and Xsalsa20Poly1305EncryptionKey2019

```bash
    npm i https://github.com/hypersign-protocol/hypersign-edv-client#dev-2.0

```

```js
    import multibase from "multibase";
    function base64toMultibase58(base64) {
        const arr=Buffer.from(base64, 'base64');
        const base58 = multibase.encode('base58btc', arr);
        return Buffer.from(base58).toString();
    }
    import {HypersignEdvClientEcdsaSecp256k1} from "@hypersign-protocol/hypersign-vault-client";

    const account = await ethereum.request({ method: 'eth_requestAccounts' });
    const publicKey = await ethereum.request({ method: 'eth_getEncryptionPublicKey', params: [account[0]] });
    const url='https://stage.hypermine.in/vault';
    const did=`did:hid:testnet:${account[0]}`
     const verificationMethod = {
        id: did+'#'+`eip155:1:${account[0]}`,
        type: 'EcdsaSecp256k1RecoveryMethod2020',
        controller: did,
        blockchainAccountId: `eip155:1:${account[0]}`,
    }

    const publicKeyMultibase=base64toMultibase58(publicKey)
    const keyAgreementKeyPair = {
        id: did + '#' + publicKeyMultibase,
        type: 'X25519KeyAgreementKeyEIP5630',
        controller: did,
        publicKeyMultibase,
    }

    const vault=new HypersignEdvClientEcdsaSecp256k1({
        url,
        keyAgreement:keyAgreementKeyPair,
        verificationMethod,
    })
    const data = {

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

       const config = {
        edvId:'urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a88',
        verificationMethod: invocationKeyPair,
        keyAgreement: keyAgreementKeyPair
    }

    const res=await vault.registerEdv(config)
    const res1=await vault.insertDoc({
        document:data,
        edvId: 'urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a88',
        recipients: [{
            id:didDocument.id.split('#')[0] + '#' + x25519.publicKeyMultibase
            type:'X25519KeyAgreementKey2020',
            }],
    })





    const decryptDoc = await vault.decryptDocument(
    {
        encryptedDocument:res1.document.encryptedData,
        recipient:{
            id: keyAgreementKeyPair.id,
            type: 'X25519KeyAgreementKeyEIP5630'
        }

    })

    const res2=await client.fetchDoc({
    edvId: 'urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a88',
    documentId: doc.document.id,
    })




```
