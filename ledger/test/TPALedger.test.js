'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const ganache = require('ganache');
const { ethers } = require('ethers');

const artifactPath = path.join(__dirname, '..', 'build', 'TPALedger.json');
const artifact = JSON.parse(fs.readFileSync(artifactPath, 'utf8'));
const ledgerInterface = new ethers.Interface(artifact.abi);

const Status = Object.freeze({ None: 0n, Active: 1n, Consumed: 2n, Revoked: 3n, Expired: 4n });
const ZERO_HASH = ethers.ZeroHash;
const hash = (label) => ethers.keccak256(ethers.toUtf8Bytes(label));

function extractRevertData(error) {
  const candidates = [];
  const seenData = new Set();
  const seenObjects = new WeakSet();

  const addCandidate = (value) => {
    if (typeof value !== 'string' || !/^0x[0-9a-fA-F]+$/.test(value) || value.length < 10) return;
    const normalized = value.toLowerCase();
    if (!seenData.has(normalized)) {
      seenData.add(normalized);
      candidates.push(value);
    }
  };

  const visit = (value, allowNestedValues = false) => {
    if (typeof value === 'string') {
      addCandidate(value);
      try { visit(JSON.parse(value), allowNestedValues); } catch { /* Non-JSON error text is not revert data. */ }
      return;
    }
    if (!value || typeof value !== 'object') return;
    if (seenObjects.has(value)) return;
    seenObjects.add(value);
    if (Array.isArray(value)) {
      value.forEach((entry) => visit(entry, allowNestedValues));
      return;
    }

    // Ethers/Ganache place EVM revert bytes in different nested envelopes for
    // static calls, gas estimates, and submitted transactions. Deliberately do
    // not walk transaction/request payloads, which contain unrelated calldata.
    for (const key of ['data', 'result', 'return', 'returnData', 'revertData', 'error', 'info', 'response', 'body']) {
      if (Object.hasOwn(value, key)) visit(value[key], key === 'data' || allowNestedValues);
    }
    if (allowNestedValues) {
      for (const nested of Object.values(value)) visit(nested, true);
    }
  };

  visit(error);
  return candidates;
}

function decodedCandidateSummary(candidates) {
  return candidates.map((data) => {
    try {
      const parsed = ledgerInterface.parseError(data);
      return parsed ? `${data.slice(0, 10)} (${parsed.name})` : data.slice(0, 10);
    } catch {
      return data.slice(0, 10);
    }
  }).join(', ') || 'none';
}

async function expectRevert(action, errorName, expectedArgs = [], message) {
  let caught;
  try {
    const result = await action();
    if (result?.wait) await result.wait();
  } catch (error) {
    caught = error;
  }
  assert.ok(caught, message || `expected ${errorName} revert`);

  const expectedError = ledgerInterface.getError(errorName);
  assert.ok(expectedError, `missing ${errorName} from TPALedger ABI`);
  const candidates = extractRevertData(caught);
  const matching = candidates.filter((data) => data.slice(0, 10).toLowerCase() === expectedError.selector.toLowerCase());
  assert.ok(
    matching.length > 0,
    `${message || 'unexpected revert'}: expected ${errorName} selector ${expectedError.selector}; ` +
      `decoded candidates: ${decodedCandidateSummary(candidates)}`
  );

  const parsed = ledgerInterface.parseError(matching[0]);
  assert.ok(parsed && parsed.name === errorName, `${message || 'unexpected revert'}: selector did not decode as ${errorName}`);
  assert.equal(parsed.args.length, expectedArgs.length, `${message || errorName}: unexpected argument count`);
  for (const [index, expected] of expectedArgs.entries()) {
    assert.deepEqual(parsed.args[index], expected, `${message || errorName}: argument ${index} mismatch`);
  }
}

describe('TPALedger (isolated local EVM)', function () {
  let eip1193;
  let provider;
  let admin;
  let recorder;
  let issuer;
  let secondIssuer;
  let attacker;
  let ledger;

  async function latestTimestamp() {
    return BigInt((await provider.getBlock('latest')).timestamp);
  }

  async function record(issuerAddress, mandateHash, ttl = 120n, signer = recorder) {
    const expiresAt = (await latestTimestamp()) + ttl;
    await (await ledger.connect(signer).recordMandate(issuerAddress, mandateHash, expiresAt)).wait();
    return expiresAt;
  }

  async function state(issuerAddress, mandateHash) {
    return ledger.getMandate(issuerAddress, mandateHash);
  }

  beforeEach(async function () {
    eip1193 = ganache.provider({
      chain: { hardfork: 'shanghai', time: new Date('2026-01-01T00:00:00Z') },
      logging: { quiet: true },
      wallet: { totalAccounts: 6, defaultBalance: 1_000 }
    });
    provider = new ethers.BrowserProvider(eip1193, undefined, { cacheTimeout: 0 });
    provider.pollingInterval = 10;
    [admin, recorder, issuer, secondIssuer, attacker] = await Promise.all(
      [0, 1, 2, 3, 4].map((index) => provider.getSigner(index))
    );
    const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, admin);
    ledger = await factory.deploy(await recorder.getAddress());
    await ledger.waitForDeployment();
  });

  afterEach(async function () {
    if (eip1193?.disconnect) eip1193.disconnect();
  });

  it('pins a Paris compile artifact and initializes the approved recorder role', async function () {
    assert.equal(artifact.evmVersion, 'paris');
    assert.match(artifact.compiler, /^0\.8\.24\+/);
    assert.equal(await ledger.hasRole(await ledger.RECORDER_ROLE(), await recorder.getAddress()), true);
    assert.equal(await ledger.hasRole(await ledger.DEFAULT_ADMIN_ROLE(), await admin.getAddress()), true);
  });

  it('governance grants, revokes, and rotates RECORDER_ROLE without reviving the retired recorder', async function () {
    const recorderRole = await ledger.RECORDER_ROLE();
    const retiringRecorder = await recorder.getAddress();
    const replacementRecorder = await secondIssuer.getAddress();
    const issuerAddress = await issuer.getAddress();

    await (await ledger.connect(admin).grantRole(recorderRole, replacementRecorder)).wait();
    assert.equal(await ledger.hasRole(recorderRole, replacementRecorder), true);
    await record(issuerAddress, hash('replacement-recorder-before-retirement'), 120n, secondIssuer);

    await (await ledger.connect(admin).revokeRole(recorderRole, retiringRecorder)).wait();
    assert.equal(await ledger.hasRole(recorderRole, retiringRecorder), false);
    const retiredAttemptExpiry = (await latestTimestamp()) + 120n;
    await expectRevert(
      () => ledger.connect(recorder).recordMandate(
        issuerAddress,
        hash('retired-recorder-denied'),
        retiredAttemptExpiry
      ),
      'AccessControlUnauthorizedAccount',
      [retiringRecorder, recorderRole],
      'revoked recorder must not retain write authority'
    );
    await record(issuerAddress, hash('replacement-recorder-after-retirement'), 120n, secondIssuer);
  });

  it('governance grants, revokes, and rotates PAUSER_ROLE while preserving the replacement pauser', async function () {
    const pauserRole = await ledger.PAUSER_ROLE();
    const retiringPauser = await admin.getAddress();
    const replacementPauser = await secondIssuer.getAddress();

    await (await ledger.connect(admin).grantRole(pauserRole, replacementPauser)).wait();
    assert.equal(await ledger.hasRole(pauserRole, replacementPauser), true);
    await (await ledger.connect(admin).revokeRole(pauserRole, retiringPauser)).wait();
    assert.equal(await ledger.hasRole(pauserRole, retiringPauser), false);
    await expectRevert(
      () => ledger.connect(admin).pause(),
      'AccessControlUnauthorizedAccount',
      [retiringPauser, pauserRole],
      'revoked pauser must not retain incident-response authority'
    );
    await (await ledger.connect(secondIssuer).pause()).wait();
    assert.equal(await ledger.paused(), true);
    await (await ledger.connect(secondIssuer).unpause()).wait();
    assert.equal(await ledger.paused(), false);
  });

  it('recovers governance administration through a rotated DEFAULT_ADMIN_ROLE holder', async function () {
    const defaultAdminRole = await ledger.DEFAULT_ADMIN_ROLE();
    const originalAdmin = await admin.getAddress();
    const recoveryAdmin = await secondIssuer.getAddress();
    const recorderRole = await ledger.RECORDER_ROLE();
    const attackerAddress = await attacker.getAddress();

    await (await ledger.connect(admin).grantRole(defaultAdminRole, recoveryAdmin)).wait();
    await (await ledger.connect(admin).revokeRole(defaultAdminRole, originalAdmin)).wait();
    assert.equal(await ledger.hasRole(defaultAdminRole, originalAdmin), false);
    assert.equal(await ledger.hasRole(defaultAdminRole, recoveryAdmin), true);
    await expectRevert(
      () => ledger.connect(admin).grantRole(recorderRole, attackerAddress),
      'AccessControlUnauthorizedAccount',
      [originalAdmin, defaultAdminRole],
      'retired governance admin must not grant operational roles'
    );

    await (await ledger.connect(secondIssuer).grantRole(defaultAdminRole, originalAdmin)).wait();
    assert.equal(await ledger.hasRole(defaultAdminRole, originalAdmin), true);
    await (await ledger.connect(admin).grantRole(recorderRole, attackerAddress)).wait();
    assert.equal(await ledger.hasRole(recorderRole, attackerAddress), true);
  });

  it('rejects a zero initial recorder at deployment', async function () {
    const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, admin);
    await expectRevert(
      () => factory.deploy(ethers.ZeroAddress),
      'ZeroRecorder',
      [],
      'zero recorder must be rejected'
    );
  });

  it('denies an unauthorized front-run/squatting record, then permits the approved recorder', async function () {
    const issuerAddress = await issuer.getAddress();
    const mandateHash = hash('front-run-squatting');
    const expiresAt = (await latestTimestamp()) + 100n;

    await expectRevert(
      () => ledger.connect(attacker).recordMandate(issuerAddress, mandateHash, expiresAt),
      'AccessControlUnauthorizedAccount',
      [await attacker.getAddress(), await ledger.RECORDER_ROLE()],
      'unapproved caller must not reserve another issuer/hash namespace'
    );
    await (await ledger.connect(recorder).recordMandate(issuerAddress, mandateHash, expiresAt)).wait();
    assert.equal(await ledger.isValid(issuerAddress, mandateHash), true);
    await expectRevert(
      () => ledger.connect(attacker).consume(issuerAddress, mandateHash),
      'AccessControlUnauthorizedAccount',
      [await attacker.getAddress(), await ledger.RECORDER_ROLE()],
      'unapproved caller must not consume a recorded attestation'
    );
  });

  it('isolates identical hashes by issuer address', async function () {
    const mandateHash = hash('same-hash-separate-issuers');
    const firstIssuer = await issuer.getAddress();
    const otherIssuer = await secondIssuer.getAddress();

    await record(firstIssuer, mandateHash);
    await record(otherIssuer, mandateHash);

    assert.equal(await ledger.isValid(firstIssuer, mandateHash), true);
    assert.equal(await ledger.isValid(otherIssuer, mandateHash), true);
    assert.notEqual(
      await ledger.mandateKey(firstIssuer, mandateHash),
      await ledger.mandateKey(otherIssuer, mandateHash)
    );
  });

  it('records a valid short-lived attestation and emits an active status transition', async function () {
    const issuerAddress = await issuer.getAddress();
    const mandateHash = hash('valid-record');
    const receipt = await (await ledger.connect(recorder).recordMandate(
      issuerAddress,
      mandateHash,
      (await latestTimestamp()) + 120n
    )).wait();
    const statusLog = receipt.logs
      .map((log) => { try { return ledger.interface.parseLog(log); } catch { return null; } })
      .find((event) => event?.name === 'MandateStatusChanged');
    const [storedStatus, effectiveStatus, expiresAt] = await state(issuerAddress, mandateHash);

    assert.equal(statusLog.args.issuer, issuerAddress);
    assert.equal(statusLog.args.mandateHash, mandateHash);
    assert.equal(statusLog.args.status, Status.Active);
    assert.equal(storedStatus, Status.Active);
    assert.equal(effectiveStatus, Status.Active);
    assert.ok(expiresAt > 0n);
  });

  it('rejects a zero issuer', async function () {
    await expectRevert(
      () => record(ethers.ZeroAddress, hash('zero-issuer')),
      'ZeroIssuer',
      [],
      'zero issuer must be rejected'
    );
    await expectRevert(
      () => ledger.isValid(ethers.ZeroAddress, hash('zero-issuer-read')),
      'ZeroIssuer',
      [],
      'validation reads must reject a zero issuer'
    );
  });

  it('rejects a zero mandate hash', async function () {
    await expectRevert(
      () => record(awaitAddress(issuer), ZERO_HASH),
      'ZeroMandateHash',
      [],
      'zero hash must be rejected'
    );
    await expectRevert(
      () => ledger.mandateKey(awaitAddress(issuer), ZERO_HASH),
      'ZeroMandateHash',
      [],
      'key derivation must reject a zero hash'
    );
  });

  it('rejects expiry at or before the recording time', async function () {
    const issuerAddress = await issuer.getAddress();
    const now = await latestTimestamp();
    await expectRevert(
      () => ledger.connect(recorder).recordMandate(issuerAddress, hash('expired-at-write'), now),
      'ExpiryNotFuture',
      [now, now],
      'already-expired attestation must be rejected'
    );
  });

  it('accepts the maximum 300-second lifetime', async function () {
    const issuerAddress = await issuer.getAddress();
    const mandateHash = hash('maximum-lifetime');
    const expiresAt = (await latestTimestamp()) + 300n;
    await (await ledger.connect(recorder).recordMandate(issuerAddress, mandateHash, expiresAt)).wait();
    assert.equal((await state(issuerAddress, mandateHash))[2], expiresAt);
  });

  it('rejects a lifetime longer than 300 seconds', async function () {
    const issuerAddress = await issuer.getAddress();
    const now = await latestTimestamp();
    const expiresAt = now + 1_000n;
    await expectRevert(
      () => ledger.connect(recorder).recordMandate(
        issuerAddress,
        hash('over-maximum-lifetime'),
        expiresAt
      ),
      'LifetimeTooLong',
      [expiresAt, now + 300n],
      'lifetime must be bounded'
    );
  });

  it('prohibits re-recording a previously used issuer/hash namespace', async function () {
    const issuerAddress = await issuer.getAddress();
    const mandateHash = hash('duplicate-record');
    await record(issuerAddress, mandateHash);
    await expectRevert(
      () => record(issuerAddress, mandateHash),
      'MandateAlreadyRecorded',
      [issuerAddress, mandateHash],
      'duplicate record must fail'
    );
  });

  it('treats expiry equality as invalid and reports Expired without mutating stored status', async function () {
    const issuerAddress = await issuer.getAddress();
    const mandateHash = hash('expiry-equality');
    const initialTime = await latestTimestamp();
    const expiresAt = initialTime + 60n;
    const receipt = await (await ledger.connect(recorder).recordMandate(issuerAddress, mandateHash, expiresAt)).wait();
    const recordTime = BigInt((await provider.getBlock(receipt.blockNumber)).timestamp);
    const secondsToExpiry = expiresAt - recordTime;
    assert.ok(secondsToExpiry > 0n, 'record must remain future-dated in its transaction block');

    await provider.send('evm_increaseTime', [Number(secondsToExpiry)]);
    await provider.send('evm_mine', []);
    assert.equal(await latestTimestamp(), expiresAt, 'test must evaluate at exact expiry equality');
    assert.equal(await ledger.isValid(issuerAddress, mandateHash), false);
    const [storedStatus, effectiveStatus] = await state(issuerAddress, mandateHash);
    assert.equal(storedStatus, Status.Active);
    assert.equal(effectiveStatus, Status.Expired);
    await expectRevert(
      () => ledger.connect(recorder).consume(issuerAddress, mandateHash),
      'MandateExpired',
      [issuerAddress, mandateHash, expiresAt],
      'consume at exact expiry must report the expired mandate'
    );
  });

  it('allows the issuer to revoke an active mandate', async function () {
    const issuerAddress = await issuer.getAddress();
    const mandateHash = hash('issuer-revoke');
    await record(issuerAddress, mandateHash);
    await (await ledger.connect(issuer).revoke(issuerAddress, mandateHash)).wait();
    const [storedStatus, effectiveStatus] = await state(issuerAddress, mandateHash);
    assert.equal(storedStatus, Status.Revoked);
    assert.equal(effectiveStatus, Status.Revoked);
    assert.equal(await ledger.isValid(issuerAddress, mandateHash), false);
  });

  it('allows an approved recorder to revoke and denies an unrelated revoker', async function () {
    const issuerAddress = await issuer.getAddress();
    const firstHash = hash('recorder-revoke');
    const secondHash = hash('attacker-revoke');
    await record(issuerAddress, firstHash);
    await record(issuerAddress, secondHash);

    await (await ledger.connect(recorder).revoke(issuerAddress, firstHash)).wait();
    assert.equal((await state(issuerAddress, firstHash))[0], Status.Revoked);
    await expectRevert(
      () => ledger.connect(attacker).revoke(issuerAddress, secondHash),
      'UnauthorizedRevoker',
      [await attacker.getAddress(), issuerAddress],
      'unrelated caller must not revoke an issuer mandate'
    );
  });

  it('consumes a valid mandate exactly once and emits consumed status', async function () {
    const issuerAddress = await issuer.getAddress();
    const mandateHash = hash('consume-once');
    await record(issuerAddress, mandateHash);
    const receipt = await (await ledger.connect(recorder).consume(issuerAddress, mandateHash)).wait();
    const statusLog = receipt.logs
      .map((log) => { try { return ledger.interface.parseLog(log); } catch { return null; } })
      .find((event) => event?.name === 'MandateStatusChanged');

    assert.equal(statusLog.args.status, Status.Consumed);
    assert.equal((await state(issuerAddress, mandateHash))[0], Status.Consumed);
    assert.equal(await ledger.isValid(issuerAddress, mandateHash), false);
    await expectRevert(
      () => ledger.connect(recorder).consume(issuerAddress, mandateHash),
      'MandateNotActive',
      [issuerAddress, mandateHash, Status.Consumed],
      'duplicate consume must fail'
    );
  });

  it('does not consume an expired mandate', async function () {
    const issuerAddress = await issuer.getAddress();
    const mandateHash = hash('expired-consume');
    const expiresAt = (await latestTimestamp()) + 10n;
    const receipt = await (await ledger.connect(recorder).recordMandate(issuerAddress, mandateHash, expiresAt)).wait();
    const recordTime = BigInt((await provider.getBlock(receipt.blockNumber)).timestamp);
    await provider.send('evm_increaseTime', [Number(expiresAt - recordTime)]);
    await provider.send('evm_mine', []);
    await expectRevert(
      () => ledger.connect(recorder).consume(issuerAddress, mandateHash),
      'MandateExpired',
      [issuerAddress, mandateHash, expiresAt],
      'consume after expiry must report the expired mandate'
    );
  });

  it('pauses record and consumption, preserves revocation for incident response, and permits authorized recovery', async function () {
    const issuerAddress = await issuer.getAddress();
    const existingHash = hash('pause-existing');
    const newHash = hash('pause-new');
    await record(issuerAddress, existingHash);
    await (await ledger.connect(admin).pause()).wait();
    assert.equal(await ledger.paused(), true);

    await expectRevert(
      () => record(issuerAddress, newHash),
      'EnforcedPause',
      [],
      'record must stop while paused'
    );
    await expectRevert(
      () => ledger.connect(recorder).consume(issuerAddress, existingHash),
      'EnforcedPause',
      [],
      'consume must stop while paused'
    );
    await (await ledger.connect(issuer).revoke(issuerAddress, existingHash)).wait();
    assert.equal((await state(issuerAddress, existingHash))[0], Status.Revoked);
    await expectRevert(
      () => ledger.connect(attacker).unpause(),
      'AccessControlUnauthorizedAccount',
      [await attacker.getAddress(), await ledger.PAUSER_ROLE()],
      'unpause must require pauser authorization'
    );

    await (await ledger.connect(admin).unpause()).wait();
    assert.equal(await ledger.paused(), false);
    await record(issuerAddress, newHash);
    assert.equal(await ledger.isValid(issuerAddress, newHash), true);
  });
});

async function awaitAddress(signer) {
  return signer.getAddress();
}
