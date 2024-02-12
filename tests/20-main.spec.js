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
  statusTypeMatches
} from '../lib/index.js';
import {
  slCredentialRevocation as SLCRevocation,
  slCredentialSuspension as SLCSuspension
} from './mock-sl-credentials.js';
import {
  CONTEXT as VC_BSL_V1_CONTEXT,
  CONTEXT_URL as VC_BSL_V1_CONTEXT_URL
} from '@digitalbazaar/vc-bitstring-status-list-context';
import {defaultDocumentLoader} from '@digitalbazaar/vc';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import jsigs from 'jsonld-signatures';
import suiteCtx2020 from 'ed25519-signature-2020-context';

const {extendContextLoader} = jsigs;

const SUITE_CONTEXT_URL = suiteCtx2020.constants.CONTEXT_URL;
const SUITE_CONTEXT = suiteCtx2020.contexts.get(SUITE_CONTEXT_URL);

const encodedList100k =
  'H4sIAAAAAAAAA-3BMQEAAADCoPVPbQsvoAAAAAAAAAAAAAAAAP4GcwM92tQwAAA';

const documents = new Map();
documents.set(VC_BSL_V1_CONTEXT_URL, VC_BSL_V1_CONTEXT);
documents.set(SUITE_CONTEXT_URL, SUITE_CONTEXT);
documents.set(SLCRevocation.id, SLCRevocation);
documents.set(SLCSuspension.id, SLCSuspension);

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
  it('should create a BitstringStatusListCredential credential', async () => {
    const id = 'https://example.com/status/1';
    const list = await createList({length: 100000});
    const credential = await createCredential(
      {id, list, statusPurpose: 'revocation'});
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
});

describe('statusTypeMatches', () => {
  it('should find a match', async () => {
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
        statusListIndex: '67342',
        statusListCredential: SLCRevocation.id
      },
      issuer: SLCRevocation.issuer,
    };
    const result = statusTypeMatches({credential});
    result.should.equal(true);
  });

  it('should not find a match', async () => {
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
        type: 'ex:NotMatch',
        statusListIndex: '67342',
        statusListCredential: SLCRevocation.id
      },
      issuer: SLCRevocation.issuer,
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
        statusListCredential: SLCRevocation.id
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
        statusListCredential: SLCRevocation.id
      },
      issuer: SLCRevocation.issuer,
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
        statusListCredential: SLCRevocation.id
      },
      issuer: SLCRevocation.issuer,
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
    const invalidSLC = JSON.parse(JSON.stringify(SLCRevocation));
    delete invalidSLC.proof;
    invalidSLC.id = 'https://example.com/status/no-proof-SLCRevocation';
    documents.set(invalidSLC.id, invalidSLC);
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
        statusListCredential: invalidSLC.id
      },
      issuer: invalidSLC.issuer,
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
      const invalidSLC = JSON.parse(JSON.stringify(SLCRevocation));
      // intentionally change it's type
      invalidSLC.type = ['VerifiableCredential', 'ex:Invalid'];
      invalidSLC.id = 'https://example.com/status/tampered-SLCRevocation';
      documents.set(invalidSLC.id, invalidSLC);
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
          statusListCredential: invalidSLC.id
        },
        issuer: invalidSLC.issuer,
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
    const invalidSLC = JSON.parse(JSON.stringify(SLCRevocation));
    delete invalidSLC.proof;
    invalidSLC.id = 'https://example.com/status/no-proof-invalid-SLCRevocation';
    documents.set(invalidSLC.id, invalidSLC);
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
        statusListCredential: invalidSLC.id
      },
      issuer: invalidSLC.issuer,
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
        statusListCredential: SLCRevocation.id
      },
      issuer: SLCRevocation.issuer,
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
        statusListCredential: SLCRevocation.id
      },
      issuer: SLCRevocation.issuer,
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
        statusListCredential: SLCRevocation.id
      }, {
        id: 'https://example.com/status/2#67343',
        type: 'BitstringStatusListEntry',
        statusPurpose: 'suspension',
        statusListIndex: '67343',
        statusListCredential: SLCSuspension.id
      }],
      issuer: SLCRevocation.issuer,
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

  it('should fail with incorrect status type', async () => {
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
        statusListCredential: SLCRevocation.id
      },
      issuer: SLCRevocation.issuer,
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
        statusListCredential: SLCRevocation.id
      }, {
        id: 'https://example.com/status/1#67342',
        type: 'ex:NonmatchingStatusType',
        statusPurpose: 'revocation',
        statusListIndex: '67342',
        statusListCredential: SLCRevocation.id
      }],
      issuer: SLCRevocation.issuer,
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

  it('should fail when missing index', async () => {
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
        statusListCredential: SLCRevocation.id
      },
      issuer: SLCRevocation.issuer,
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
      issuer: SLCSuspension.issuer,
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
        statusListCredential: SLCRevocation.id
      },
      issuer: SLCRevocation.issuer,
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
      issuer: SLCRevocation.issuer,
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
    const invalidSLC = JSON.parse(JSON.stringify(SLCRevocation));
    // intentionally set SLCRevocation type to an invalid type
    invalidSLC.type = ['InvalidType'];
    invalidSLC.id = 'https://example.com/status/invalid-SLCRevocation-type';

    documents.set(invalidSLC.id, invalidSLC);

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
        statusListCredential: invalidSLC.id
      },
      issuer: SLCRevocation.issuer,
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
    const invalidSLC = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://www.w3.org/ns/credentials/status/v1',
        'https://w3id.org/security/suites/ed25519-2020/v1',
        {'@vocab': 'https://invalid'}
      ],
      id: 'https://example.com/status/1',
      issuer: 'did:key:z6MksyNRT8R43D9uTjZUBUL6bkypRMJFdUhJw3cQR5Nfu4an',
      issuanceDate: '2022-06-02T16:00:21Z',
      type: [ 'VerifiableCredential', 'BitstringStatusListCredential' ],
      credentialSubject: {
        id: 'https://example.com/status/1#list',
        type: 'InvalidType',
        encodedList: 'H4sIAAAAAAAAA-3OMQ0AAAgDsOHfNB72EJJWQRMAAAAAAIDWXAcAAAA' +
          'AAIDHFrc4zDzUMAAA',
        statusPurpose: 'revocation'
      },
      proof: {
        type: 'Ed25519Signature2020',
        created: '2024-02-09T20:07:29Z',
        verificationMethod: 'did:key:z6MksyNRT8R43D9uTjZUBUL6bkypRMJFdUhJw3c' +
          'QR5Nfu4an#z6MksyNRT8R43D9uTjZUBUL6bkypRMJFdUhJw3cQR5Nfu4an',
        proofPurpose: 'assertionMethod',
        proofValue: 'z21FCoyGBuS3PA961EAiExh4DFp7zjAtimCgowdocER6CzuJCyhxsdK' +
          'AeCJRv9ABfeRxQg5GJdTvgtWa3eW9xJKai'
      }
    };

    documents.set(invalidSLC.id, invalidSLC);

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
        statusListCredential: invalidSLC.id
      },
      issuer: invalidSLC.issuer,
    };
    const suite = new Ed25519Signature2020();
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
    const invalidSLC = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://www.w3.org/ns/credentials/status/v1',
        'https://w3id.org/security/suites/ed25519-2020/v1'
      ],
      id: 'https://example.com/status/1',
      issuer: 'did:key:z6MkhepELN9L2iLwoGTzAEx5M9vA38y7AbnXk9fTgfTtVvSE',
      issuanceDate: '2022-06-02T16:00:21Z',
      type: [ 'VerifiableCredential', 'BitstringStatusListCredential' ],
      credentialSubject: {
        id: 'https://example.com/status/1#list',
        type: 'BitstringStatusList',
        encodedList: 'Invalid-XYZ',
        statusPurpose: 'revocation'
      },
      proof: {
        type: 'Ed25519Signature2020',
        created: '2024-02-09T19:55:53Z',
        verificationMethod: 'did:key:z6MkhepELN9L2iLwoGTzAEx5M9vA38y7AbnXk9fT' +
          'gfTtVvSE#z6MkhepELN9L2iLwoGTzAEx5M9vA38y7AbnXk9fTgfTtVvSE',
        proofPurpose: 'assertionMethod',
        proofValue: 'z32AG82ncrFxcRGw3H7WTTVtLPWEyW95zoxMNcHxTKbeNphFScZXJFAz' +
          'b7qw3CdoGMWFCqKexGvQXiHoAkHdBpyPt'
      }
    };

    documents.set(invalidSLC.id, invalidSLC);

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
        statusListCredential: invalidSLC.id
      },
      issuer: invalidSLC.issuer,
    };
    const suite = new Ed25519Signature2020();
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
        statusListCredential: SLCRevocation.id
      }
    };
    const documentLoader = 'https://example.com/status/1';
    const suite = new Ed25519Signature2020();
    const result = await checkStatus({
      suite,
      credential,
      documentLoader,
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
        statusListCredential: SLCRevocation.id
      }
    };
    const documentLoader = extendContextLoader(async url => {
      const doc = documents.get(url);
      if(doc) {
        return {
          contextUrl: null,
          documentUrl: url,
          document: doc
        };
      }
      return defaultDocumentLoader(url);
    });
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
    const credential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        VC_BSL_V1_CONTEXT_URL
      ],
      id: 'urn:uuid:e74fb1d6-7926-11ea-8e11-10bf48838a41',
      issuer: SLCRevocation.issuer,
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
        statusListCredential: SLCRevocation.id
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
        statusListCredential: SLCRevocation.id,
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
        statusListCredential: SLCRevocation.id,
      },
      // this issuer does not match the issuer for the mock SLC specified
      // by `SLC.id` above
      issuer: 'did:example:1234',
    };
    documents.set(SLCRevocation.id, SLCRevocation);

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

  it('should fail when "CONTEXTS.VC_BSL_V1" or "CONTEXTS.VC_V2" are not in ' +
    '"@context"', async () => {
    const id = 'https://example.com/status/1';
    const list = await createList({length: 100000});
    const credential = await createCredential(
      {id, list, statusPurpose: 'revocation'});
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
      statusListCredential: SLCRevocation.id
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
      statusListCredential: SLCSuspension.id
    },
    {
      id: 'https://example.com/status/1#67342',
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: '67342',
      statusListCredential: SLCRevocation.id
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
      statusListCredential: SLCRevocation.id
    },
    {
      id: 'https://example.com/status/1#67342',
      type: 'ex:NonmatchingStatusType',
      statusPurpose: 'suspension',
      statusListIndex: '67342',
      statusListCredential: SLCSuspension.id
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
      statusListCredential: SLCRevocation.id
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
      statusListCredential: SLCRevocation.id
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
      statusListCredential: SLCRevocation.id
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
