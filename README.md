# @digitalbazaar/vc-bitstring-status-list

[Verifiable Credential Bitstring Status List](https://github.com/w3c/vc-bitstring-status-list/)

### Creating a BitstringStatusListCredential

```js
import {
  BitstringStatusList,
  createCredential,
  VC_BSL_VC_V1_CONTEXT,
  VC_BSL_VC_V2_CONTEXT
} from '@digitalbazaar/vc-bitstring-status-list';
import {documentLoader} from './path-to/document-loader.js';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {Ed25519VerificationKey2020} from
  '@digitalbazaar/ed25519-verification-key-2020';
import {issue} from '@digitalbazaar/vc';

// Issuer Setup
const key = new Ed25519VerificationKey2020({
  id: 'did:key:z6Mkrjy3khhKz1jPLEwhqYAWNn3xMURog2DdCqjWAmD6anRE#z6Mkrjy3khhKz1jPLEwhqYAWNn3xMURog2DdCqjWAmD6anRE',
  controller: 'did:key:z6Mkrjy3khhKz1jPLEwhqYAWNn3xMURog2DdCqjWAmD6anRE',
  publicKeyMultibase: 'z6Mkrjy3khhKz1jPLEwhqYAWNn3xMURog2DdCqjWAmD6anRE',
  privateKeyMultibase: 'zrv5NrLP4CvUQPGqpoFFCq6ihnEJWF7DpA1r13cxqzeJcSWjbgpXabWbCuHPUUSYhCknd3qWxEfT2ax7cR8TcYr4Dkt'
})
const suite = new Ed25519Signature2020({key});

// Status List Details
const id = 'https://example.com/credentials/status/3';
const list = new BitstringStatusList({length: 100000});
const statusPurpose = 'revocation';

// Create BitstringStatusListCredential
const credential = await createCredential({
  id,
  list,
  statusPurpose,
  context: VC_BSL_VC_V2_CONTEXT // OR VC_BSL_VC_V1_CONTEXT for VCDM v1
});

// Create BitstringStatusListCredential Verifiable Credential
const statusVC = await issue({credential, suite, documentLoader})
```

### Create a Verifiable Credential which uses a BitstringStatusList

```js
// see imports above
const credential = {
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    'https://www.w3.org/2018/credentials/examples/v1',
    'https://www.w3.org/ns/credentials/status/v1'
  ],
  id: 'https://example.com/credentials/3732',
  type: ['VerifiableCredential', 'UniversityDegreeCredential'],
  issuer: suite.key.controller,
  issuanceDate: '2021-03-10T04:24:12.164Z',
  credentialStatus: {
    id: 'https://example.com/credentials/status/3#94567',
    type: 'BitstringStatusListEntry',
    statusListIndex: '94567',
    statusListCredential: 'https://example.com/credentials/status/3'
  },
  credentialSubject: {
    id: 'did:web:did.actor:bob',
    degree: {
      type: 'BachelorDegree',
      name: 'Bachelor of Science and Arts',
    }
  }
};
let verifiableCredential = await issue({
  credential: {...credential},
  suite,
  documentLoader
});
```
