# @digitalbazaar/vc-bitstring-status-list

[Verifiable Credential Bitstring Status List1](https://github.com/w3c/vc-bitstring-status-list/)

### Creating a BitstringStatusListCredential

```js
const sl = require("@digitalbazaar/vc-bitstring-status-list");
const jsigs = require("jsonld-signatures");
const {Ed25519KeyPair} = require("crypto-ld");
const vc = require("vc-js");
const documentLoader = require("./path-to/document-loader.js");

const key = new Ed25519KeyPair({
  "id": "did:key:z6MknUVLM84Eo5mQswCqP7f6oNER84rmVKkCvypob8UtBC8K#z6MknUVLM84Eo5mQswCqP7f6oNER84rmVKkCvypob8UtBC8K",
  "controller": "did:key:z6MknUVLM84Eo5mQswCqP7f6oNER84rmVKkCvypob8UtBC8K",
  "type": "Ed25519VerificationKey2018",
  "privateKeyBase58": "CoZphRAfAVPqx9f54MRUBtmjD4uY6KPxQQKsE3frUbZ269tBD4AdTQAVbXHHgpewh4BunoXK8dotcUJ6JXhZPsh",
  "publicKeyBase58": "92EHksooTYGwmSN8hYhFxGgRJVav5SVrExuskrWsFyLw"
});
const suite = new Ed25519Signature2018({
  key,
  date: "2019-12-11T03:50:55Z",
});
const id = "https://example.com/credentials/status/3";
const list = await sl.createList({length: 100000});
const encodedList = await list.encode();
const slCredential = {
  "@context": ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/ns/credentails/status/v1"],
  id,
  issuer: "did:key:z6MknUVLM84Eo5mQswCqP7f6oNER84rmVKkCvypob8UtBC8K",
  issuanceDate: "2021-03-10T04:24:12.164Z",
  type: ["VerifiableCredential", "BitstringStatusListCredential"],
  credentialSubject: {
    id: `${id}#list`,
    type: "BitstringStatusList",
    encodedList,
  },
};
let verifiableCredential = await vc.issue({
  credential: {...slCredential},
  suite,
  documentLoader,
});
```

### Created a Credential which uses a BitstringStatusList

```js
// see imports above
const credential = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1",
    "https://www.w3.org/ns/credentials/status/v1",
  ],
  id: "https://example.com/credentials/3732",
  type: ["VerifiableCredential", "UniversityDegreeCredential"],
  issuer: "did:web:did.actor:alice",
  issuanceDate: "2021-03-10T04:24:12.164Z",
  credentialStatus: {
    id: "https://example.com/credentials/status/3#94567",
    type: "BitstringStatusListEntry",
    statusListIndex: "94567",
    statusListCredential:
      "https://did.actor/alice/credentials/status/3",
  },
  credentialSubject: {
    id: "did:web:did.actor:bob",
    degree: {
      type: "BachelorDegree",
      name: "Bachelor of Science and Arts",
    },
  },
};
let verifiableCredential = await vc.issue({
  credential: {...credential},
  suite,
  documentLoader,
});
```
