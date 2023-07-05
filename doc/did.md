# Data Vault Supported DID typs

### Supported DID Document Configurations

1. DID TYPE 1
   ```JSON
   {
       "@context": [
           "https://www.w3.org/ns/did/v1"
       ],
       "id": "did:hid:testnet:z8jKN9U1kkBo1prTabZn5izw7TAMf7GPD7ARLrcqFtpAW",
       "controller": [
           "did:hid:testnet:z8jKN9U1kkBo1prTabZn5izw7TAMf7GPD7ARLrcqFtpAW"
       ],
       "alsoKnownAs": [
           "did:hid:testnet:z8jKN9U1kkBo1prTabZn5izw7TAMf7GPD7ARLrcqFtpAW"
       ],
       "verificationMethod": [
           {
               "id": "did:hid:testnet:z8jKN9U1kkBo1prTabZn5izw7TAMf7GPD7ARLrcqFtpAW#key-1",
               "type": "Ed25519VerificationKey2020",
               "controller": "did:hid:testnet:z8jKN9U1kkBo1prTabZn5izw7TAMf7GPD7ARLrcqFtpAW",
               "publicKeyMultibase": "z8jKN9U1kkBo1prTabZn5izw7TAMf7GPD7ARLrcqFtpAW",
               "blockchainAccountId": ""
           },
           {
               "id": "did:hid:testnet:z8jKN9U1kkBo1prTabZn5izw7TAMf7GPD7ARLrcqFtpAW#key-2",
               "type": "X25519KeyAgreementKey2019",
               "controller": "did:hid:testnet:z8jKN9U1kkBo1prTabZn5izw7TAMf7GPD7ARLrcqFtpAW",
               "publicKeyMultibase": "z8jKnlgjkagioauggadglaksgolkanajg",
           }
       ],
       "authentication": [
           "did:hid:testnet:z8jKN9U1kkBo1prTabZn5izw7TAMf7GPD7ARLrcqFtpAW#key-1"
       ],
       "assertionMethod": [
           "did:hid:testnet:z8jKN9U1kkBo1prTabZn5izw7TAMf7GPD7ARLrcqFtpAW#key-1"
       ],
       "keyAgreement": [
           "did:hid:testnet:z8jKN9U1kkBo1prTabZn5izw7TAMf7GPD7ARLrcqFtpAW#key-2"
       ],
       "capabilityInvocation": [
           "did:hid:testnet:z8jKN9U1kkBo1prTabZn5izw7TAMf7GPD7ARLrcqFtpAW#key-1"
       ],
       "capabilityDelegation": [
           "did:hid:testnet:z8jKN9U1kkBo1prTabZn5izw7TAMf7GPD7ARLrcqFtpAW#key-1"
       ],
       "service": []
   }
   ```
2. DID TYPE 2

   ```JSON
       {
           @context:["https://www.w3.org/ns/did/v1"],
           id:"did:hid:testnet:0x54ceff083c2c71b8e23b7a98bac91cf65883e880",
           controller:["did:hid:testnet:0x54ceff083c2c71b8e23b7a98bac91cf65883e880"],
           alsoKnownAs:["did:hid:testnet:0x54ceff083c2c71b8e23b7a98bac91cf65883e880"],
           verificationMethod:[
               {
                   id:"did:hid:testnet:0x54ceff083c2c71b8e23b7a98bac91cf65883e880#key-1",
                   type:"EcdsaSecp256k1RecoveryMethod2020",
                   controller:"did:hid:testnet:0x54ceff083c2c71b8e23b7a98bac91cf65883e880",
                   blockchainAccountId:"eip155:1:0x54ceff083c2c71b8e23b7a98bac91cf65883e880"
               },
               {
                   id:"did:hid:testnet:0x54ceff083c2c71b8e23b7a98bac91cf65883e880#key-2",
                   type:"X25519KeyAgreementKeyEIP5630",
                   controller:"did:hid:testnet:0x54ceff083c2c71b8e23b7a98bac91cf65883e880",
                   publicKeyMultibase:"z5VEZKctV8uQ4bYdzmdr3e4JVbdL2bfgf6gc4qSnEseEt",
               }
           ],
           authentication:[
               "did:hid:testnet:0x54ceff083c2c71b8e23b7a98bac91cf65883e880#key-1"
           ],
           assertionMethod:[
               "did:hid:testnet:0x54ceff083c2c71b8e23b7a98bac91cf65883e880#key-1"
           ],
           keyAgreement:[
               "did:hid:testnet:0x54ceff083c2c71b8e23b7a98bac91cf65883e880#key-2"
           ],
           capabilityInvocation:[
               "did:hid:testnet:0x54ceff083c2c71b8e23b7a98bac91cf65883e880#key-1"
           ],
           capabilityDelegation:[
               "did:hid:testnet:0x54ceff083c2c71b8e23b7a98bac91cf65883e880#key-1"
           ],
           service:[]
       }

   ```
