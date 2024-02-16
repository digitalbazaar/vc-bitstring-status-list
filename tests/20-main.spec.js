/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as didKey from '@digitalbazaar/did-method-key';
import {
  assertBitstringStatusListContext,
  checkStatus,
  createCredential,
  createList,
  decodeList,
  getCredentialStatus,
  statusTypeMatches,
  VC_BSL_VC_V1_CONTEXT
} from '../lib/index.js';
import {defaultDocumentLoader, issue} from '@digitalbazaar/vc';
import {
  CONTEXT as VC_BSL_V1_CONTEXT,
  CONTEXT_URL as VC_BSL_V1_CONTEXT_URL
} from '@digitalbazaar/vc-bitstring-status-list-context';
import {
  createMockBitstringStatusListCredential
} from './mock-sl-credentials.js';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {Ed25519VerificationKey2020} from
  '@digitalbazaar/ed25519-verification-key-2020';
import jsigs from 'jsonld-signatures';
import suiteCtx2020 from 'ed25519-signature-2020-context';

const {extendContextLoader} = jsigs;

const SUITE_CONTEXT_URL = suiteCtx2020.constants.CONTEXT_URL;
const SUITE_CONTEXT = suiteCtx2020.contexts.get(SUITE_CONTEXT_URL);

const encodedList100k =
  'uH4sIAAAAAAAAA-3BMQEAAADCoPVPbQsvoAAAAAAAAAAAAAAAAP4GcwM92tQwAAA';

const documents = new Map();
documents.set(VC_BSL_V1_CONTEXT_URL, VC_BSL_V1_CONTEXT);
documents.set(SUITE_CONTEXT_URL, SUITE_CONTEXT);
// documents.set(SLCRevocation.id, SLCRevocation);
// documents.set(SLCSuspension.id, SLCSuspension);

const didKeyDriver = didKey.driver();

const documentLoader = extendContextLoader(async url => {
  let doc;
  if(url.startsWith('did:key:')) {
    doc = await didKeyDriver.get({url});
  } else {
    doc = documents.get(url);
  }
  if(doc) {
    return {
      contextUrl: null,
      documentUrl: url,
      document: doc
    };
  }
  return defaultDocumentLoader(url);
});

describe('createList', () => {
  it('should pass', async () => {
    const list = await createList({length: 8});
    should.exist(list.bitstring);
    should.exist(list.length);
    list.length.should.equal(8);
  });

  it('should fail when "length" param is missing', async () => {
    let err;
    try {
      await createList();
    } catch(e) {
      err = e;
    }
    should.exist(err);
    err.name.should.equal('TypeError');
  });
});

describe('decodeList', () => {
  it('should pass', async () => {
    const list = await decodeList({encodedList: encodedList100k});
    list.length.should.equal(100000);
  });

  it('should fail', async () => {
    let err;
    try {
      await decodeList({encodedList: 'INVALID-XYZ'});
    } catch(e) {
      err = e;
    }
    should.exist(err);
    err.message.should.include('Could not decode encoded status list');
  });
});

describe('createCredential', () => {
  it('should fail when "id" argument missing', async () => {
    let err;
    try {
      await createCredential({
        list: await createList({length: 8}),
        statusPurpose: 'revocation'
      });
    } catch(e) {
      err = e;
    }
    should.exist(err);
    err.message.should.equal('"id" is required.');
  });
  it('should fail when "list" argument missing', async () => {
    let err;
    try {
      await createCredential({
        id: 'https://example.com/1',
        statusPurpose: 'revocation'
      });
    } catch(e) {
      err = e;
    }
    should.exist(err);
    err.message.should.equal('"list" is required.');
  });
  it('should fail when "list" argument not "BitstringStatusList"', async () => {
    let err;
    try {
      await createCredential({
        id: 'https://example.com/1',
        list: encodedList100k,
        statusPurpose: 'revocation'
      });
    } catch(e) {
      err = e;
    }
    should.exist(err);
    err.message.should.equal('"list" is required.');
  });
  it('should fail when "statusPurpose" argument missing', async () => {
    let err;
    try {
      await createCredential({
        id: 'https://example.com/1',
        list: await createList({length: 8})
      });
    } catch(e) {
      err = e;
    }
    should.exist(err);
    err.message.should.equal('"statusPurpose" is required.');
  });
  it('should create a BitstringStatusListCredential credential ' +
    'with VCDM v1', async () => {
    const id = 'https://example.com/status/1';
    const list = await createList({length: 100000});
    const credential = await createCredential(
      {
        id, list, statusPurpose: 'revocation',
        context: [
          'https://www.w3.org/2018/credentials/v1',
          VC_BSL_V1_CONTEXT_URL
        ]
      });
    credential.should.be.an('object');
    credential.should.deep.equal({
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        VC_BSL_V1_CONTEXT_URL
      ],
      id,
      type: ['VerifiableCredential', 'BitstringStatusListCredential'],
      credentialSubject: {
        id: `${id}#list`,
        type: 'BitstringStatusList',
        encodedList: encodedList100k,
        statusPurpose: 'revocation'
      }
    });
  });
  it('should create a BitstringStatusListCredential credential ' +
    'with VCDM v2', async () => {
    const id = 'https://example.com/status/1';
    const list = await createList({length: 100000});
    const credential = await createCredential(
      {id, list, statusPurpose: 'revocation'});
    credential.should.be.an('object');
    credential.should.deep.equal({
      '@context': [
        'https://www.w3.org/ns/credentials/v2'
      ],
      id,
      type: ['VerifiableCredential', 'BitstringStatusListCredential'],
      credentialSubject: {
        id: `${id}#list`,
        type: 'BitstringStatusList',
        encodedList: encodedList100k,
        statusPurpose: 'revocation'
      }
    });
  });
});

describe('statusTypeMatches', () => {
  it('should find a match', async () => {
    const credential = {
      '@context': VC_BSL_VC_V1_CONTEXT,
      id: 'urn:uuid:a0418a78-7924-11ea-8a23-10bf48838a41',
      type: ['VerifiableCredential', 'example:TestCredential'],
      credentialSubject: {
        id: 'urn:uuid:4886029a-7925-11ea-9274-10bf48838a41',
        'example:test': 'foo'
      },
      credentialStatus: {
        id: 'https://example.com/status/1#67342',
        type: 'BitstringStatusListEntry',
        statusListIndex: '67342',
        statusListCredential: 'https://example.com/status/1'
      },
      issuer: 'did:key:z6MkowtnRyMkCerXvXqjCYUo2mLEeCgX1sWfoP2CZA5UjBop'
    };
    const result = statusTypeMatches({credential});
    result.should.equal(true);
  });

  it('should not find a match', async () => {
    const credential = {
      '@context': VC_BSL_VC_V1_CONTEXT,
      id: 'urn:uuid:a0418a78-7924-11ea-8a23-10bf48838a41',
      type: ['VerifiableCredential', 'example:TestCredential'],
      credentialSubject: {
        id: 'urn:uuid:4886029a-7925-11ea-9274-10bf48838a41',
        'example:test': 'foo'
      },
      credentialStatus: {
        id: 'https://example.com/status/1#67342',
        type: 'ex:NotMatch',
        statusListIndex: '67342',
        statusListCredential: 'https://example.com/status/1'
      },
      issuer: 'did:key:z6MkowtnRyMkCerXvXqjCYUo2mLEeCgX1sWfoP2CZA5UjBop',
    };
    const result = statusTypeMatches({credential});
    result.should.equal(false);
  });

  it('should fail when "credential" is not an object', async () => {
    let err;
    let result;
    try {
      result = statusTypeMatches({credential: ''});
    } catch(e) {
      err = e;
    }
    should.exist(err);
    should.not.exist(result);
    err.should.be.instanceof(TypeError);
    err.message.should.contain('"credential" must be an object');
  });

  it('should fail when "@context" is not an array', async () => {
    const id = 'https://example.com/status/1';
    const list = await createList({length: 100000});
    const credential = await createCredential(
      {id, list, statusPurpose: 'revocation'});
    let err;
    let result;
    try {
      // change the @context property to a string
      credential['@context'] = id;
      result = statusTypeMatches({credential});
    } catch(e) {
      err = e;
    }
    should.exist(err);
    should.not.exist(result);
    err.should.be.instanceof(TypeError);
    err.message.should.contain('"@context" must be an array');
  });

  it('should fail when first "@context" value is unexpected', async () => {
    const id = 'https://example.com/status/1';
    const list = await createList({length: 100000});
    const credential = await createCredential(
      {id, list, statusPurpose: 'revocation'});
    let err;
    let result;
    try {
      // change the @context property intentionally to an unexpected value
      credential['@context'][0] = 'https://example.com/test/1';
      result = statusTypeMatches({credential});
    } catch(e) {
      err = e;
    }
    should.exist(err);
    should.not.exist(result);
    err.should.be.instanceof(Error);
    err.message.should.contain('first "@context" value');
  });

  it('should fail when "credentialStatus" does not exist', async () => {
    const id = 'https://example.com/status/1';
    const list = await createList({length: 100000});
    const credential = await createCredential(
      {id, list, statusPurpose: 'revocation'});
    let err;
    let result;
    try {
      // remove required credentialStatus property
      delete credential.credentialStatus;
      result = statusTypeMatches({credential});
    } catch(e) {
      err = e;
    }
    should.not.exist(err);
    result.should.equal(false);
  });

  it('should fail when "credentialStatus" is not an object in ' +
    '"statusTypeMatches"', async () => {
    const id = 'https://example.com/status/1';
    const list = await createList({length: 100000});
    const credential = await createCredential(
      {id, list, statusPurpose: 'revocation'});
    let err;
    let result;
    try {
      // change credentialStatus to a string type
      credential.credentialStatus = 'https://example.com/status/1#50000';
      result = statusTypeMatches({credential});
    } catch(e) {
      err = e;
    }
    should.exist(err);
    should.not.exist(result);
    err.should.be.instanceof(Error);
    err.message.should.contain('"credentialStatus" is invalid');
  });

  it('should not match when "CONTEXTS.VC_BSL_V1" or "CONTEXTS.VC_2" are not ' +
    'in "@context"', async () => {
    const id = 'https://example.com/status/1';
    const list = await createList({length: 100000});
    const credential = await createCredential(
      {id, list, statusPurpose: 'revocation'});
    let err;
    let result;
    try {
      delete credential['@context'][1];
      credential.credentialStatus = {
        id: 'https://example.com/status/1#50000',
        type: 'BitstringStatusListEntry',
        statusListIndex: '50000',
        statusListCredential: 'https://example.com/status/1'
      };
      result = statusTypeMatches({credential});
    } catch(e) {
      err = e;
    }
    should.not.exist(err);
    result.should.equal(false);
  });
});

describe('checkStatus', () => {
  it('should verify a valid status list vc', async () => {
    const statusVC = await createMockBitstringStatusListCredential({
      statusPurpose: 'revocation', documentLoader
    });
    documents.set(statusVC.id, statusVC);
    const credential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        VC_BSL_V1_CONTEXT_URL
      ],
      id: 'urn:uuid:a0418a78-7924-11ea-8a23-10bf48838a41',
      type: ['VerifiableCredential', 'example:TestCredential'],
      credentialSubject: {
        id: 'urn:uuid:4886029a-7925-11ea-9274-10bf48838a41',
        'example:test': 'foo'
      },
      credentialStatus: {
        id: 'https://example.com/status/1#67342',
        type: 'BitstringStatusListEntry',
        statusPurpose: 'revocation',
        statusListIndex: '67342',
        statusListCredential: statusVC.id
      },
      issuer: statusVC.issuer,
    };
    const suite = new Ed25519Signature2020();
    const result = await checkStatus({
      credential,
      suite,
      documentLoader,
      verifyStatusListCredential: true
    });
    should.not.exist(result.error);
    result.verified.should.equal(true);
    should.exist(result.results);
    result.results.should.be.lengthOf(1);
    result.results.should.have.deep.members(
      [{verified: true, credentialStatus: credential.credentialStatus}]);
  });

  it('should use default value when "verifyStatusListCredential" is not ' +
    'specified', async () => {
    const statusVC = await createMockBitstringStatusListCredential({
      statusPurpose: 'revocation', documentLoader
    });
    documents.set('https://example.com/status/1', statusVC);
    const credential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        VC_BSL_V1_CONTEXT_URL
      ],
      id: 'urn:uuid:a0418a78-7924-11ea-8a23-10bf48838a41',
      type: ['VerifiableCredential', 'example:TestCredential'],
      credentialSubject: {
        id: 'urn:uuid:4886029a-7925-11ea-9274-10bf48838a41',
        'example:test': 'foo'
      },
      credentialStatus: {
        id: 'https://example.com/status/1#67342',
        type: 'BitstringStatusListEntry',
        statusPurpose: 'revocation',
        statusListIndex: '67342',
        statusListCredential: statusVC.id
      },
      issuer: statusVC.issuer,
    };
    const suite = new Ed25519Signature2020();
    const result = await checkStatus({
      credential,
      suite,
      documentLoader,
    });
    should.not.exist(result.error);
    result.verified.should.equal(true);
  });

  it('should fail to verify an invalid status list vc', async () => {
    const statusVC = await createMockBitstringStatusListCredential({
      statusPurpose: 'revocation', documentLoader
    });
    delete statusVC.proof;
    statusVC.id = 'https://example.com/status/no-proof-BSLCRevocation';
    documents.set(statusVC.id, statusVC);
    const credential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        VC_BSL_V1_CONTEXT_URL
      ],
      id: 'urn:uuid:a0418a78-7924-11ea-8a23-10bf48838a41',
      type: ['VerifiableCredential', 'example:TestCredential'],
      credentialSubject: {
        id: 'urn:uuid:4886029a-7925-11ea-9274-10bf48838a41',
        'example:test': 'foo'
      },
      credentialStatus: {
        id: 'https://example.com/status/1#67342',
        type: 'BitstringStatusListEntry',
        statusPurpose: 'revocation',
        statusListIndex: '67342',
        statusListCredential: statusVC.id
      },
      issuer: statusVC.issuer,
    };
    const suite = new Ed25519Signature2020();
    const result = await checkStatus({
      credential,
      suite,
      documentLoader,
      verifyStatusListCredential: true
    });
    result.verified.should.equal(false);
    should.exist(result.error);
    result.error.cause.errors[0].message.should.equal(
      'No matching proofs found in the given document.');
  });

  it('should fail to verify status list vc that has been tampered with',
    async () => {
      const statusVC = await createMockBitstringStatusListCredential({
        statusPurpose: 'revocation', documentLoader
      });
      statusVC.type = ['VerifiableCredential', 'ex:Invalid'];
      statusVC.id = 'https://example.com/status/tampered-SLCRevocation';
      documents.set(statusVC.id, statusVC);
      const credential = {
        '@context': [
          'https://www.w3.org/2018/credentials/v1',
          VC_BSL_V1_CONTEXT_URL
        ],
        id: 'urn:uuid:a0418a78-7924-11ea-8a23-10bf48838a41',
        type: ['VerifiableCredential', 'example:TestCredential'],
        credentialSubject: {
          id: 'urn:uuid:4886029a-7925-11ea-9274-10bf48838a41',
          'example:test': 'foo'
        },
        credentialStatus: {
          id: 'https://example.com/status/1#67342',
          type: 'BitstringStatusListEntry',
          statusPurpose: 'revocation',
          statusListIndex: '67342',
          statusListCredential: statusVC.id
        },
        issuer: statusVC.issuer,
      };
      const suite = new Ed25519Signature2020();
      const result = await checkStatus({
        credential,
        suite,
        documentLoader,
        verifyStatusListCredential: true
      });
      result.verified.should.equal(false);
      should.exist(result.error);
      result.error.cause.errors[0].message.should.equal('Invalid signature.');
    });

  it('should verify with an invalid status list vc when ' +
    '"verifyStatusListCredential" is set to "false"', async () => {
    const statusVC = await createMockBitstringStatusListCredential({
      statusPurpose: 'revocation', documentLoader
    });
    delete statusVC.proof;
    statusVC.id = 'https://example.com/status/no-proof-invalid-SLCRevocation';
    documents.set(statusVC.id, statusVC);
    const credential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        VC_BSL_V1_CONTEXT_URL
      ],
      id: 'urn:uuid:a0418a78-7924-11ea-8a23-10bf48838a41',
      type: ['VerifiableCredential', 'example:TestCredential'],
      credentialSubject: {
        id: 'urn:uuid:4886029a-7925-11ea-9274-10bf48838a41',
        'example:test': 'foo'
      },
      credentialStatus: {
        id: 'https://example.com/status/1#67342',
        type: 'BitstringStatusListEntry',
        statusPurpose: 'revocation',
        statusListIndex: '67342',
        statusListCredential: statusVC.id
      },
      issuer: statusVC.issuer,
    };
    const suite = new Ed25519Signature2020();
    const result = await checkStatus({
      credential,
      suite,
      documentLoader,
      verifyBitstringStatusListCredential: false
    });
    should.not.exist(result.error);
    result.verified.should.equal(true);
  });

  it('should verify one status of a credential', async () => {
    const statusVC = await createMockBitstringStatusListCredential({
      statusPurpose: 'revocation', documentLoader
    });
    documents.set(statusVC.id, statusVC);
    const credential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        VC_BSL_V1_CONTEXT_URL
      ],
      id: 'urn:uuid:a0418a78-7924-11ea-8a23-10bf48838a41',
      type: ['VerifiableCredential', 'example:TestCredential'],
      credentialSubject: {
        id: 'urn:uuid:4886029a-7925-11ea-9274-10bf48838a41',
        'example:test': 'foo'
      },
      credentialStatus: {
        id: 'https://example.com/status/1#67342',
        type: 'BitstringStatusListEntry',
        statusPurpose: 'revocation',
        statusListIndex: '67342',
        statusListCredential: statusVC.id
      },
      issuer: statusVC.issuer,
    };
    const suite = new Ed25519Signature2020();
    const result = await checkStatus({
      credential,
      suite,
      documentLoader,
      verifyStatusListCredential: true
    });
    should.not.exist(result.error);
    result.verified.should.equal(true);
  });

  it('should fail to verify if status purpose in credential does not match ' +
    'the status purpose of status list credential', async () => {
    const statusVC = await createMockBitstringStatusListCredential({
      statusPurpose: 'revocation', documentLoader
    });
    documents.set(statusVC.id, statusVC);
    const credential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        VC_BSL_V1_CONTEXT_URL
      ],
      id: 'urn:uuid:a0418a78-7924-11ea-8a23-10bf48838a41',
      type: ['VerifiableCredential', 'example:TestCredential'],
      credentialSubject: {
        id: 'urn:uuid:4886029a-7925-11ea-9274-10bf48838a41',
        'example:test': 'foo'
      },
      credentialStatus: {
        id: 'https://example.com/status/2#67342',
        type: 'BitstringStatusListEntry',
        statusPurpose: 'suspension',
        statusListIndex: '67342',
        // intentionally point the statusListCredential to the
        // status list credential with status purpose "revocation".
        statusListCredential: statusVC.id
      },
      issuer: statusVC.issuer,
    };
    const suite = new Ed25519Signature2020();
    const result = await checkStatus({
      credential,
      suite,
      documentLoader,
      verifyStatusListCredential: true
    });
    should.exist(result.error);
    result.error.message.should.equal(
      'The status purpose "revocation" of the status list credential does ' +
      'not match the status purpose "suspension" in the credential.');
    result.verified.should.equal(false);
  });

  it('should verify multiple statuses of a credential', async () => {
    const keyPair = await Ed25519VerificationKey2020.generate();
    const {publicKeyMultibase} = keyPair;
    keyPair.id = `did:key:${publicKeyMultibase}#${publicKeyMultibase}`;
    keyPair.controller = `did:key:${publicKeyMultibase}`;
    const suite = new Ed25519Signature2020({key: keyPair});
    const statusVCRevocation = await createMockBitstringStatusListCredential({
      suite, statusPurpose: 'revocation', documentLoader
    });
    const statusVCSuspension = await createMockBitstringStatusListCredential({
      suite, id: 'https://example.com/status/2', statusPurpose: 'suspension',
      documentLoader
    });
    documents.set(statusVCRevocation.id, statusVCRevocation);
    documents.set(statusVCSuspension.id, statusVCSuspension);
    const credential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        VC_BSL_V1_CONTEXT_URL
      ],
      id: 'urn:uuid:a0418a78-7924-11ea-8a23-10bf48838a41',
      type: ['VerifiableCredential', 'example:TestCredential'],
      credentialSubject: {
        id: 'urn:uuid:4886029a-7925-11ea-9274-10bf48838a41',
        'example:test': 'foo'
      },
      credentialStatus: [{
        id: 'https://example.com/status/1#67342',
        type: 'BitstringStatusListEntry',
        statusPurpose: 'revocation',
        statusListIndex: '67342',
        statusListCredential: statusVCRevocation.id
      }, {
        id: 'https://example.com/status/2#67343',
        type: 'BitstringStatusListEntry',
        statusPurpose: 'suspension',
        statusListIndex: '67343',
        statusListCredential: statusVCSuspension.id
      }],
      issuer: statusVCRevocation.issuer,
    };
    const result = await checkStatus({
      credential,
      suite,
      documentLoader,
      verifyStatusListCredential: true
    });
    should.not.exist(result.error);
    result.verified.should.equal(true);
  });

  it('should fail with incorrect status type', async () => {
    const statusVC = await createMockBitstringStatusListCredential({
      statusPurpose: 'revocation', documentLoader
    });
    documents.set(statusVC.id, statusVC);
    const credential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        VC_BSL_V1_CONTEXT_URL
      ],
      id: 'urn:uuid:a0418a78-7924-11ea-8a23-10bf48838a41',
      type: ['VerifiableCredential', 'example:TestCredential'],
      credentialSubject: {
        id: 'urn:uuid:4886029a-7925-11ea-9274-10bf48838a41',
        'example:test': 'foo'
      },
      credentialStatus: {
        id: 'https://example.com/status/1#67342',
        type: 'ex:NonmatchingStatusType',
        statusListIndex: '67342',
        statusListCredential: statusVC.id
      },
      issuer: statusVC.issuer,
    };
    const suite = new Ed25519Signature2020();
    const result = await checkStatus({
      credential,
      suite,
      documentLoader,
      verifyStatusListCredential: true
    });
    result.verified.should.equal(false);
    should.exist(result.error);
    result.error.message.should.equal('"credentialStatus.type" must be ' +
      '"BitstringStatusListEntry".');
  });

  it('should pass when there is >= 1 matching type', async () => {
    const keyPair = await Ed25519VerificationKey2020.generate();
    const {publicKeyMultibase} = keyPair;
    keyPair.id = `did:key:${publicKeyMultibase}#${publicKeyMultibase}`;
    keyPair.controller = `did:key:${publicKeyMultibase}`;
    const suite = new Ed25519Signature2020({key: keyPair});
    const statusVCRevocation = await createMockBitstringStatusListCredential({
      suite, statusPurpose: 'revocation', documentLoader
    });
    const statusVCRevocation2 = await createMockBitstringStatusListCredential({
      suite, id: 'https://example.com/status/2', statusPurpose: 'revocation',
      documentLoader
    });
    documents.set(statusVCRevocation.id, statusVCRevocation);
    documents.set(statusVCRevocation2.id, statusVCRevocation2);
    const credential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        VC_BSL_V1_CONTEXT_URL
      ],
      id: 'urn:uuid:a0418a78-7924-11ea-8a23-10bf48838a41',
      type: ['VerifiableCredential', 'example:TestCredential'],
      credentialSubject: {
        id: 'urn:uuid:4886029a-7925-11ea-9274-10bf48838a41',
        'example:test': 'foo'
      },
      credentialStatus: [{
        id: 'https://example.com/status/1#67342',
        type: 'BitstringStatusListEntry',
        statusPurpose: 'revocation',
        statusListIndex: '67342',
        statusListCredential: statusVCRevocation.id
      }, {
        id: 'https://example.com/status/2#67342',
        type: 'ex:NonmatchingStatusType',
        statusPurpose: 'revocation',
        statusListIndex: '67342',
        statusListCredential: statusVCRevocation2.id
      }],
      issuer: statusVCRevocation.issuer,
    };
    const result = await checkStatus({
      credential,
      suite,
      documentLoader,
      verifyStatusListCredential: true
    });
    should.not.exist(result.error);
    result.verified.should.equal(true);
  });

  it('should fail when missing index', async () => {
    const statusVC = await createMockBitstringStatusListCredential({
      statusPurpose: 'revocation', documentLoader
    });
    documents.set(statusVC.id, statusVC);
    const credential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        VC_BSL_V1_CONTEXT_URL
      ],
      id: 'urn:uuid:a0418a78-7924-11ea-8a23-10bf48838a41',
      type: ['VerifiableCredential', 'example:TestCredential'],
      credentialSubject: {
        id: 'urn:uuid:4886029a-7925-11ea-9274-10bf48838a41',
        'example:test': 'foo'
      },
      credentialStatus: {
        id: 'https://example.com/status/1#67342',
        type: 'BitstringStatusListEntry',
        statusPurpose: 'revocation',
        statusListCredential: statusVC.id
      },
      issuer: statusVC.issuer,
    };
    const suite = new Ed25519Signature2020();
    const result = await checkStatus({
      credential,
      suite,
      documentLoader,
      verifyStatusListCredential: true
    });
    result.verified.should.equal(false);
    should.exist(result.error);
    result.error.message.should.equal('"statusListIndex" must be an integer.');
  });

  it('should fail when missing "statusListCredential"', async () => {
    const statusVC = await createMockBitstringStatusListCredential({
      statusPurpose: 'suspension', documentLoader
    });
    documents.set(statusVC.id, statusVC);
    const credential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        VC_BSL_V1_CONTEXT_URL
      ],
      id: 'urn:uuid:a0418a78-7924-11ea-8a23-10bf48838a41',
      type: ['VerifiableCredential', 'example:TestCredential'],
      credentialSubject: {
        id: 'urn:uuid:4886029a-7925-11ea-9274-10bf48838a41',
        'example:test': 'foo'
      },
      credentialStatus: {
        id: 'https://example.com/status/1#67342',
        type: 'BitstringStatusListEntry',
        statusPurpose: 'suspension',
        statusListIndex: '67342'
      },
      issuer: statusVC.issuer,
    };
    const suite = new Ed25519Signature2020();
    const result = await checkStatus({
      credential,
      suite,
      documentLoader,
      verifyStatusListCredential: true
    });
    result.verified.should.equal(false);
    should.exist(result.error);
    result.error.message.should.equal(
      '"credentialStatus.statusListCredential" must be a string.');
  });

  it('should fail when missing "statusPurpose"', async () => {
    const statusVC = await createMockBitstringStatusListCredential({
      statusPurpose: 'revocation', documentLoader
    });
    documents.set(statusVC.id, statusVC);
    const credential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        VC_BSL_V1_CONTEXT_URL
      ],
      id: 'urn:uuid:e74fb1d6-7926-11ea-8e11-10bf48838a41',
      type: ['VerifiableCredential', 'example:TestCredential'],
      credentialSubject: {
        id: 'urn:uuid:011e064e-7927-11ea-8975-10bf48838a41',
        'example:test': 'bar'
      },
      credentialStatus: {
        id: 'https://example.com/status/1#50000',
        type: 'BitstringStatusListEntry',
        statusListIndex: '50000',
        statusListCredential: statusVC.id
      },
      issuer: statusVC.issuer,
    };
    const suite = new Ed25519Signature2020();
    const result = await checkStatus({
      credential,
      suite,
      documentLoader,
      verifyStatusListCredential: true
    });
    result.verified.should.equal(false);
    should.exist(result.error);
    result.error.message.should.equal(
      '"credentialStatus.statusPurpose" must be a string.');
  });

  it('should fail when documentLoader cannot load ' +
    '"statusListCredential"', async () => {
    const statusVC = await createMockBitstringStatusListCredential({
      statusPurpose: 'revocation', documentLoader
    });
    const credential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        VC_BSL_V1_CONTEXT_URL
      ],
      id: 'urn:uuid:e74fb1d6-7926-11ea-8e11-10bf48838a41',
      type: ['VerifiableCredential', 'example:TestCredential'],
      credentialSubject: {
        id: 'urn:uuid:011e064e-7927-11ea-8975-10bf48838a41',
        'example:test': 'bar'
      },
      credentialStatus: {
        id: 'https://example.com/status/1#50000',
        type: 'BitstringStatusListEntry',
        statusPurpose: 'revocation',
        statusListIndex: '50000',
        // intentionally set statusListCredential to an id that is not set
        // in documents
        statusListCredential: 'https://example.com/status/3'
      },
      issuer: statusVC.issuer,
    };
    const suite = new Ed25519Signature2020();
    const result = await checkStatus({
      credential,
      suite,
      documentLoader,
      verifyStatusListCredential: true
    });
    result.verified.should.equal(false);
    should.exist(result.error);
    result.error.message.should.equal(
      'Could not load "BitstringStatusListCredential"; ' +
      'reason: Document loader unable to load URL ' +
      '"https://example.com/status/3".');
  });

  it('should fail when "statusListCredential" type does not ' +
    'include "BitstringStatusListCredential"', async () => {
    const statusVC = await createMockBitstringStatusListCredential({
      statusPurpose: 'revocation', documentLoader
    });
    documents.set(statusVC.id, statusVC);
    // intentionally set SLCRevocation type to an invalid type
    statusVC.type = ['InvalidType'];
    statusVC.id = 'https://example.com/status/invalid-SLCRevocation-type';
    documents.set(statusVC.id, statusVC);

    const credential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        VC_BSL_V1_CONTEXT_URL
      ],
      id: 'urn:uuid:e74fb1d6-7926-11ea-8e11-10bf48838a41',
      type: ['VerifiableCredential', 'example:TestCredential'],
      credentialSubject: {
        id: 'urn:uuid:011e064e-7927-11ea-8975-10bf48838a41',
        'example:test': 'bar'
      },
      credentialStatus: {
        id: 'https://example.com/status/1#50000',
        type: 'BitstringStatusListEntry',
        statusPurpose: 'revocation',
        statusListIndex: '50000',
        statusListCredential: statusVC.id
      },
      issuer: statusVC.issuer,
    };
    const suite = new Ed25519Signature2020();
    const result = await checkStatus({
      credential, documentLoader, suite,
      verifyBitstringStatusListCredential: false
    });
    result.verified.should.equal(false);
    should.exist(result.error);
    result.error.message.should.equal('Status list credential type must ' +
      'include "BitstringStatusListCredential".');
  });

  it('should fail when "credentialSubject" type is not ' +
    '"BitstringStatusList"', async () => {
    const keyPair = await Ed25519VerificationKey2020.generate();
    const {publicKeyMultibase} = keyPair;
    keyPair.id = `did:key:${publicKeyMultibase}#${publicKeyMultibase}`;
    keyPair.controller = `did:key:${publicKeyMultibase}`;
    const suite = new Ed25519Signature2020({key: keyPair});
    let statusVC = await createMockBitstringStatusListCredential({
      suite, statusPurpose: 'revocation', documentLoader
    });
    delete statusVC.proof;
    statusVC.credentialSubject.type = ['ex:InvalidType'];
    statusVC = await issue({credential: statusVC, suite, documentLoader});
    documents.set(statusVC.id, statusVC);

    const credential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        VC_BSL_V1_CONTEXT_URL
      ],
      id: 'urn:uuid:e74fb1d6-7926-11ea-8e11-10bf48838a41',
      type: ['VerifiableCredential', 'example:TestCredential'],
      credentialSubject: {
        id: 'urn:uuid:011e064e-7927-11ea-8975-10bf48838a41',
        'example:test': 'bar'
      },
      credentialStatus: {
        id: 'https://example.com/status/1#50000',
        type: 'BitstringStatusListEntry',
        statusPurpose: 'revocation',
        statusListIndex: '50000',
        statusListCredential: statusVC.id
      },
      issuer: statusVC.issuer,
    };
    const result = await checkStatus({
      credential, documentLoader, suite, verifyStatusListCredential: false
    });
    result.verified.should.equal(false);
    should.exist(result.error);
    result.error.message.should.equal('Status list type must be ' +
      '"BitstringStatusList".');
  });

  it('should fail when "credentialSubject.encodedList" ' +
    'cannot not be decoded', async () => {
    const keyPair = await Ed25519VerificationKey2020.generate();
    const {publicKeyMultibase} = keyPair;
    keyPair.id = `did:key:${publicKeyMultibase}#${publicKeyMultibase}`;
    keyPair.controller = `did:key:${publicKeyMultibase}`;
    const suite = new Ed25519Signature2020({key: keyPair});
    let statusVC = await createMockBitstringStatusListCredential({
      suite, statusPurpose: 'revocation', documentLoader
    });
    delete statusVC.proof;
    statusVC.credentialSubject.encodedList = 'uBAAAAAADLIST';
    statusVC = await issue({credential: statusVC, suite, documentLoader});
    documents.set(statusVC.id, statusVC);

    const credential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        VC_BSL_V1_CONTEXT_URL
      ],
      id: 'urn:uuid:e74fb1d6-7926-11ea-8e11-10bf48838a41',
      type: ['VerifiableCredential', 'example:TestCredential'],
      credentialSubject: {
        id: 'urn:uuid:011e064e-7927-11ea-8975-10bf48838a41',
        'example:test': 'bar'
      },
      credentialStatus: {
        id: 'https://example.com/status/1#50000',
        type: 'BitstringStatusListEntry',
        statusPurpose: 'revocation',
        statusListIndex: '50000',
        statusListCredential: statusVC.id
      },
      issuer: statusVC.issuer,
    };
    const result = await checkStatus({
      credential, documentLoader, suite, verifyStatusListCredential: false
    });
    result.verified.should.equal(false);
    should.exist(result.error);
    result.error.message.should.equal('Could not decode encoded status ' +
      'list; reason: incorrect header check');
  });

  it('should fail when missing "credential" param', async () => {
    const suite = new Ed25519Signature2020();
    const result = await checkStatus({
      suite,
      documentLoader,
      verifyStatusListCredential: true
    });
    should.exist(result);
    result.should.be.an('object');
    result.should.have.property('verified');
    result.verified.should.be.a('boolean');
    result.verified.should.equal(false);
    result.should.have.property('error');
    result.error.should.be.instanceof(TypeError);
    result.error.message.should.contain('"credential" must be an object');
  });

  it('should fail when documentLoader is not a function', async () => {
    const statusVC = await createMockBitstringStatusListCredential({
      statusPurpose: 'revocation', documentLoader
    });
    documents.set(statusVC.id, statusVC);
    const credential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        VC_BSL_V1_CONTEXT_URL
      ],
      id: 'urn:uuid:a0418a78-7924-11ea-8a23-10bf48838a41',
      type: ['VerifiableCredential', 'example:TestCredential'],
      credentialSubject: {
        id: 'urn:uuid:4886029a-7925-11ea-9274-10bf48838a41',
        'example:test': 'foo'
      },
      credentialStatus: {
        id: 'https://example.com/status/1#67342',
        type: 'BitstringStatusListEntry',
        statusListCredential: statusVC.id
      }
    };
    const documentLoader2 = 'https://example.com/status/1';
    const suite = new Ed25519Signature2020();
    const result = await checkStatus({
      suite,
      credential,
      documentLoader: documentLoader2,
      verifyStatusListCredential: true
    });

    should.exist(result);
    result.should.be.an('object');
    result.should.have.property('verified');
    result.verified.should.be.a('boolean');
    result.verified.should.be.false;
    result.should.have.property('error');
    result.error.should.be.instanceof(TypeError);
    result.error.message.should.contain(
      '"documentLoader" must be a function');
  });

  it('should fail when suite is not an object or array of ' +
    'objects', async () => {
    const statusVC = await createMockBitstringStatusListCredential({
      statusPurpose: 'revocation', documentLoader
    });
    documents.set(statusVC.id, statusVC);
    const credential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        VC_BSL_V1_CONTEXT_URL
      ],
      id: 'urn:uuid:e74fb1d6-7926-11ea-8e11-10bf48838a41',
      type: ['VerifiableCredential', 'example:TestCredential'],
      credentialSubject: {
        id: 'urn:uuid:011e064e-7927-11ea-8975-10bf48838a41',
        'example:test': 'bar'
      },
      credentialStatus: {
        id: 'https://example.com/status/1#50000',
        type: 'BitstringStatusListEntry',
        statusListIndex: '50000',
        statusListCredential: statusVC.id
      }
    };
    const suite = '{}';
    let err;
    let result;
    try {
      result = await checkStatus({
        credential, documentLoader, suite, verifyStatusListCredential: true
      });
    } catch(e) {
      err = e;
    }
    should.not.exist(err);
    should.exist(result);
    result.should.be.an('object');
    result.should.have.property('verified');
    result.verified.should.be.a('boolean');
    result.verified.should.be.false;
    result.should.have.property('error');
    result.error.should.be.instanceof(TypeError);
    result.error.message.should.contain(
      '"suite" must be an object or an array of objects');
  });

  it('should fail when "BitstringStatusListCredential" is not ' +
    'verified', async () => {
    const statusVC = await createMockBitstringStatusListCredential({
      statusPurpose: 'revocation', documentLoader
    });
    documents.set(statusVC.id, statusVC);
    const credential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        VC_BSL_V1_CONTEXT_URL
      ],
      id: 'urn:uuid:e74fb1d6-7926-11ea-8e11-10bf48838a41',
      issuer: statusVC.issuer,
      issuanceDate: '2021-03-10T04:24:12.164Z',
      type: ['VerifiableCredential', 'example:TestCredential'],
      credentialSubject: {
        id: 'urn:uuid:011e064e-7927-11ea-8975-10bf48838a41',
        'example:test': 'bar'
      },
      credentialStatus: {
        id: 'https://example.com/status/1#50000',
        type: 'BitstringStatusListEntry',
        statusPurpose: 'revocation',
        statusListIndex: 50000,
        statusListCredential: statusVC.id
      }
    };
    let err;
    let result;
    try {
      // `SLC` is not a valid status list credential, so any call with
      // `verifyStatusListCredential: true` with a credential that references
      // `SLC.id` will always fail
      result = await checkStatus({
        credential, documentLoader, suite: {}, verifyStatusListCredential: true
      });
    } catch(e) {
      err = e;
    }
    should.not.exist(err);
    should.exist(result);
    result.should.be.an('object');
    result.should.have.property('verified');
    result.verified.should.be.a('boolean');
    result.verified.should.be.false;
    result.should.have.property('error');
    result.error.should.be.instanceof(Error);
    result.error.message.should.contain(
      '"BitstringStatusListCredential" not verified');
  });

  it('should fail for non-matching credential issuers', async () => {
    const credential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        VC_BSL_V1_CONTEXT_URL,
      ],
      id: 'urn:uuid:a0418a78-7924-11ea-8a23-10bf48838a41',
      type: ['VerifiableCredential', 'example:TestCredential'],
      credentialSubject: {
        id: 'urn:uuid:4886029a-7925-11ea-9274-10bf48838a41',
        'example:test': 'foo',
      },
      credentialStatus: {
        id: 'https://example.com/status/1#67342',
        type: 'BitstringStatusListEntry',
        statusPurpose: 'revocation',
        statusListIndex: '67342',
        statusListCredential: 'https://example.com/status/1',
      },
      // this issuer does not match the issuer for the mock SLC specified
      // by `SLC.id` above
      issuer: 'did:example:1234',
    };
    const suite = new Ed25519Signature2020();
    const result = await checkStatus({
      suite,
      credential,
      documentLoader,
      verifyStatusListCredential: true,
      verifyMatchingIssuers: true,
    });
    result.verified.should.equal(false);
    should.exist(result.error);
    result.error.message.should.equal('Issuers of the status list credential ' +
      'and verifiable credential do not match.');
  });

  it('should allow different issuers when "verifyMatchingIssuers" is ' +
    'false', async () => {
    const statusVC = await createMockBitstringStatusListCredential({
      statusPurpose: 'revocation', documentLoader
    });
    documents.set(statusVC.id, statusVC);
    const credential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        VC_BSL_V1_CONTEXT_URL,
      ],
      id: 'urn:uuid:a0418a78-7924-11ea-8a23-10bf48838a41',
      type: ['VerifiableCredential', 'example:TestCredential'],
      credentialSubject: {
        id: 'urn:uuid:4886029a-7925-11ea-9274-10bf48838a41',
        'example:test': 'foo',
      },
      credentialStatus: {
        id: 'https://example.com/status/1#67342',
        type: 'BitstringStatusListEntry',
        statusPurpose: 'revocation',
        statusListIndex: '67342',
        statusListCredential: statusVC.id,
      },
      // this issuer does not match the issuer for the mock SLC specified
      // by `SLC.id` above
      issuer: 'did:example:1234',
    };

    const suite = new Ed25519Signature2020();
    const result = await checkStatus({
      credential,
      suite,
      documentLoader,
      verifyStatusListCredential: true,
      // this flag is set to allow different values for credential.issuer and
      // SLC.issuer
      verifyMatchingIssuers: false,
    });
    should.not.exist(result.error);
    result.verified.should.equal(true);
  });
});

describe('assertBitstringStatusListContext', () => {
  it('should pass when "@context" includes "CONTEXTS.VC_V2"', async () => {
    const id = 'https://example.com/status/1';
    const list = await createList({length: 100000});
    const credential = await createCredential(
      {id, list, statusPurpose: 'revocation'});

    let err;
    let result;
    try {
      result = assertBitstringStatusListContext({credential});
    } catch(e) {
      err = e;
    }
    should.not.exist(err);
    should.not.exist(result);
  });

  it('should fail when "credential" is not an object', async () => {
    let err;
    let result;
    try {
      result = assertBitstringStatusListContext({credential: ''});
    } catch(e) {
      err = e;
    }
    should.exist(err);
    should.not.exist(result);
    err.should.be.instanceof(TypeError);
    err.message.should.contain('"credential" must be an object');
  });

  it('should fail when "@context" is not an array', async () => {
    const id = 'https://example.com/status/1';
    const list = await createList({length: 100000});
    const credential = await createCredential(
      {id, list, statusPurpose: 'revocation'});
    let err;
    let result;
    try {
      // change the @context property to a string
      credential['@context'] = 'https://example.com/status/1';
      result = assertBitstringStatusListContext({credential});
    } catch(e) {
      err = e;
    }
    should.exist(err);
    should.not.exist(result);
    err.should.be.instanceof(TypeError);
    err.message.should.contain('"@context" must be an array');
  });

  it('should fail when first "@context" value is unexpected', async () => {
    const id = 'https://example.com/status/1';
    const list = await createList({length: 100000});
    const credential = await createCredential(
      {id, list, statusPurpose: 'revocation'});
    let err;
    let result;
    try {
      // change the @context property intentionally to an unexpected value
      credential['@context'][0] = 'https://example.com/test/1';
      result = assertBitstringStatusListContext({credential});
    } catch(e) {
      err = e;
    }
    should.exist(err);
    should.not.exist(result);
    err.should.be.instanceof(Error);
    err.message.should.contain('first "@context" value');
  });

  it('should fail when "CONTEXTS.VC_BSL_V1" not in VCDM v1 credential ' +
    '"@context"', async () => {
    const id = 'https://example.com/status/1';
    const list = await createList({length: 100000});
    const credential = await createCredential(
      {id, list, statusPurpose: 'revocation', context: [
        'https://www.w3.org/2018/credentials/v1',
        VC_BSL_V1_CONTEXT_URL,
      ]});
    let err;
    let result;
    try {
      delete credential['@context'][1];
      result = assertBitstringStatusListContext({credential});
    } catch(e) {
      err = e;
    }
    should.exist(err);
    should.not.exist(result);
    err.should.be.instanceof(TypeError);
    err.message.should.contain('@context" must include');
  });
});

describe('getCredentialStatus', () => {
  it('should fail when "credential" is not an object', async () => {
    let err;
    let result;
    try {
      result = getCredentialStatus({credential: ''});
    } catch(e) {
      err = e;
    }
    should.exist(err);
    should.not.exist(result);
    err.should.be.instanceof(TypeError);
    err.message.should.contain('"credential" must be an object');
  });

  it('should fail when "credentialStatus" is not an object', async () => {
    const id = 'https://example.com/status/1';
    const list = await createList({length: 100000});
    const credential = await createCredential(
      {id, list, statusPurpose: 'revocation'});
    let err;
    let result;
    try {
      delete credential.credentialStatus;
      result = getCredentialStatus({credential, statusPurpose: 'revocation'});
    } catch(e) {
      err = e;
    }
    should.exist(err);
    should.not.exist(result);
    err.should.be.instanceof(Error);
    err.message.should.contain('"credentialStatus" is missing or invalid');
  });

  it('should fail when "credentialStatus.type" is not ' +
    '"BitstringStatusListEntry"', async () => {
    const id = 'https://example.com/status/1';
    const list = await createList({length: 100000});
    const credential = await createCredential(
      {id, list, statusPurpose: 'revocation'});
    credential.credentialStatus = {
      id: 'https://example.com/status/1#67342',
      type: 'InvalidType',
      statusPurpose: 'revocation',
      statusListIndex: '67342',
      statusListCredential: 'https://example.com/status/1'
    };
    let err;
    let result;
    try {
      result = getCredentialStatus({credential, statusPurpose: 'revocation'});
    } catch(e) {
      err = e;
    }
    should.exist(err);
    should.not.exist(result);
    err.should.be.instanceof(Error);
    err.message.should.contain('"credentialStatus" with type ' +
      '"BitstringStatusListEntry" and status purpose "revocation" not found.');
  });

  it('should fail when "credentialStatus.id" is not a string', async () => {
    const id = 'https://example.com/status/1';
    const list = await createList({length: 100000});
    const credential = await createCredential(
      {id, list, statusPurpose: 'revocation'});
    credential.credentialStatus = {
      id: 6,
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: '67342',
      statusListCredential: 'https://example.com/status/1'
    };
    let err;
    let result;
    try {
      result = getCredentialStatus({credential, statusPurpose: 'revocation'});
    } catch(e) {
      err = e;
    }
    should.exist(err);
    should.not.exist(result);
    err.should.be.instanceof(Error);
    err.message.should.contain('"credentialStatus.id" must be a string.');
  });

  it('should fail when "credentialStatus.id" is the same as ' +
    '"credentialStatus.statusListCredential"', async () => {
    const id = 'https://example.com/status/1';
    const list = await createList({length: 100000});
    const credential = await createCredential(
      {id, list, statusPurpose: 'revocation'});
    credential.credentialStatus = {
      id: 'https://example.com/status/1#67342',
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: '67342',
      statusListCredential: 'https://example.com/status/1#67342'
    };
    let err;
    let result;
    try {
      result = getCredentialStatus({credential, statusPurpose: 'revocation'});
    } catch(e) {
      err = e;
    }
    should.exist(err);
    should.not.exist(result);
    err.should.be.instanceof(Error);
    err.message.should.contain('"credentialStatus.id" must not be ' +
      '"credentialStatus.statusListCredential".');
  });

  it('should pass when credential has >= 1 credential status ' +
    'with correct type', async () => {
    const id = 'https://example.com/status/1';
    const list = await createList({length: 100000});
    const credential = await createCredential(
      {id, list, statusPurpose: 'revocation'});
    credential.credentialStatus = [{
      id: 'https://example.com/status/2#67342',
      type: 'ex:NonmatchingStatusType',
      statusPurpose: 'suspension',
      statusListIndex: '67342',
      statusListCredential: 'https://example.com/status/2'
    },
    {
      id: 'https://example.com/status/1#67342',
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: '67342',
      statusListCredential: 'https://example.com/status/1'
    }];
    let err;
    let result;
    try {
      result = getCredentialStatus({credential, statusPurpose: 'revocation'});
    } catch(e) {
      err = e;
    }
    should.not.exist(err);
    should.exist(result);
    result.should.eql(credential.credentialStatus[1]);
  });

  it('should fail when "credential.credentialStatus" is an empty ' +
    'array', async () => {
    const id = 'https://example.com/status/1';
    const list = await createList({length: 100000});
    const credential = await createCredential(
      {id, list, statusPurpose: 'revocation'});
    credential.credentialStatus = [ ];
    let err;
    let result;
    try {
      result = getCredentialStatus({credential, statusPurpose: 'revocation'});
    } catch(e) {
      err = e;
    }
    should.exist(err);
    should.not.exist(result);
    err.message.should.equal('"credentialStatus" with type ' +
      '"BitstringStatusListEntry" and status purpose "revocation" not found.');
  });

  it('should fail when "credential.credentialStatus" has no status with type ' +
    'matching "BitstringStatusListEntry"', async () => {
    const id = 'https://example.com/status/1';
    const list = await createList({length: 100000});
    const credential = await createCredential(
      {id, list, statusPurpose: 'revocation'});
    credential.credentialStatus = [{
      id: 'https://example.com/status/1#12345',
      type: 'ex:NonmatchingStatusType',
      statusPurpose: 'revocation',
      statusListIndex: '12345',
      statusListCredential: 'https://example.com/status/1'
    },
    {
      id: 'https://example.com/status/1#67342',
      type: 'ex:NonmatchingStatusType',
      statusPurpose: 'suspension',
      statusListIndex: '67342',
      statusListCredential: 'https://example.com/status/2'
    }];
    let err;
    let result;
    try {
      result = getCredentialStatus({credential, statusPurpose: 'revocation'});
    } catch(e) {
      err = e;
    }
    should.exist(err);
    should.not.exist(result);
    err.message.should.equal('"credentialStatus" with type ' +
      '"BitstringStatusListEntry" and status purpose "revocation" not found.');
  });

  it('should pass "credentialStatus" when "credentialStatus.type" is ' +
    '"BitstringStatusListEntry" and "statusPurpose" matches', async () => {
    const id = 'https://example.com/status/1';
    const list = await createList({length: 100000});
    const credential = await createCredential(
      {id, list, statusPurpose: 'revocation'});
    credential.credentialStatus = {
      id: 'https://example.com/status/1#67342',
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: '67342',
      statusListCredential: 'https://example.com/status/1'
    };
    let err;
    let result;
    try {
      result = getCredentialStatus({credential, statusPurpose: 'revocation'});
    } catch(e) {
      err = e;
    }
    should.not.exist(err);
    should.exist(result);
    result.should.eql(credential.credentialStatus);
  });

  it('should fail when "statusPurpose" is not specified', async () => {
    const id = 'https://example.com/status/1';
    const list = await createList({length: 100000});
    const credential = await createCredential(
      {id, list, statusPurpose: 'revocation'});
    credential.credentialStatus = {
      id: 'https://example.com/status/1#67342',
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: '67342',
      statusListCredential: 'https://example.com/status/1'
    };
    let err;
    let result;
    try {
      result = getCredentialStatus({credential});
    } catch(e) {
      err = e;
    }
    should.exist(err);
    should.not.exist(result);
    err.name.should.equal('TypeError');
    err.message.should.equal('"statusPurpose" must be a string.');
  });

  it('should fail when "statusPurpose" does not match ' +
    '"credentialStatus.statusPurpose"', async () => {
    const id = 'https://example.com/status/1';
    const list = await createList({length: 100000});
    const credential = await createCredential(
      {id, list, statusPurpose: 'revocation'});
    credential.credentialStatus = {
      id: 'https://example.com/status/1#67342',
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: '67342',
      statusListCredential: 'https://example.com/status/1'
    };
    let err;
    let result;
    try {
      result = getCredentialStatus({credential, statusPurpose: 'suspension'});
    } catch(e) {
      err = e;
    }
    should.exist(err);
    should.not.exist(result);
    err.should.be.instanceof(Error);
    err.message.should.contain('"credentialStatus" with type ' +
      '"BitstringStatusListEntry" and status purpose "suspension" not found.');
  });
});
