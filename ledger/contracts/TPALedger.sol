// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ITPALedger} from "./ITPALedger.sol";

/// @title TPALedger
/// @notice A namespaced registry of short-lived attestations made by an approved verifier server.
/// @dev This contract does NOT verify WebAuthn/passkey signatures. A trusted backend must perform
/// WebAuthn verification before an account holding RECORDER_ROLE calls recordMandate. It does NOT
/// custody or move funds, prove assets, execute payments, or prove settlement.
contract TPALedger is AccessControl, Pausable, ITPALedger {
    bytes32 public constant RECORDER_ROLE = keccak256("RECORDER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /// @notice Absolute maximum validity window from the recording block timestamp.
    uint64 public constant MAX_LIFETIME = 300;

    struct Mandate {
        Status status;
        uint64 expiresAt;
    }

    mapping(address issuer => mapping(bytes32 mandateHash => Mandate)) private _mandates;

    error ZeroIssuer();
    error ZeroMandateHash();
    error ZeroRecorder();
    error ExpiryNotFuture(uint64 expiresAt, uint256 currentTimestamp);
    error LifetimeTooLong(uint64 expiresAt, uint256 latestAllowedTimestamp);
    error MandateAlreadyRecorded(address issuer, bytes32 mandateHash);
    error MandateNotFound(address issuer, bytes32 mandateHash);
    error MandateNotActive(address issuer, bytes32 mandateHash, Status currentStatus);
    error MandateExpired(address issuer, bytes32 mandateHash, uint64 expiresAt);
    error UnauthorizedRevoker(address caller, address issuer);

    /// @notice Emits every stored-status transition with the affected namespace and actor.
    event MandateStatusChanged(
        address indexed issuer,
        bytes32 indexed mandateHash,
        Status status,
        address indexed actor,
        uint64 expiresAt
    );

    /// @notice Deploys an empty registry and approves the initial verifier-server recorder.
    /// @param initialRecorder Address controlled by the trusted verification backend.
    constructor(address initialRecorder) {
        if (initialRecorder == address(0)) revert ZeroRecorder();

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);
        _grantRole(RECORDER_ROLE, initialRecorder);
    }

    /// @notice Stops new records and consumption. Revocation remains available during a pause.
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Resumes records and consumption after an authorized operational recovery.
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /// @inheritdoc ITPALedger
    function recordMandate(address issuer, bytes32 mandateHash, uint64 expiresAt)
        external
        onlyRole(RECORDER_ROLE)
        whenNotPaused
    {
        _validateNamespace(issuer, mandateHash);

        uint256 currentTimestamp = block.timestamp;
        if (expiresAt <= currentTimestamp) revert ExpiryNotFuture(expiresAt, currentTimestamp);

        uint256 latestAllowedTimestamp = currentTimestamp + MAX_LIFETIME;
        if (uint256(expiresAt) > latestAllowedTimestamp) {
            revert LifetimeTooLong(expiresAt, latestAllowedTimestamp);
        }

        Mandate storage mandate = _mandates[issuer][mandateHash];
        if (mandate.status != Status.None) revert MandateAlreadyRecorded(issuer, mandateHash);

        mandate.status = Status.Active;
        mandate.expiresAt = expiresAt;

        emit MandateStatusChanged(issuer, mandateHash, Status.Active, msg.sender, expiresAt);
    }

    /// @inheritdoc ITPALedger
    function consume(address issuer, bytes32 mandateHash)
        external
        onlyRole(RECORDER_ROLE)
        whenNotPaused
    {
        _validateNamespace(issuer, mandateHash);
        Mandate storage mandate = _mandates[issuer][mandateHash];
        _requireActiveAndUnexpired(issuer, mandateHash, mandate);

        mandate.status = Status.Consumed;
        emit MandateStatusChanged(issuer, mandateHash, Status.Consumed, msg.sender, mandate.expiresAt);
    }

    /// @inheritdoc ITPALedger
    /// @dev Revocation intentionally remains callable while paused so an issuer or recorder can
    /// invalidate a previously recorded attestation during incident response.
    function revoke(address issuer, bytes32 mandateHash) external {
        _validateNamespace(issuer, mandateHash);
        if (msg.sender != issuer && !hasRole(RECORDER_ROLE, msg.sender)) {
            revert UnauthorizedRevoker(msg.sender, issuer);
        }

        Mandate storage mandate = _mandates[issuer][mandateHash];
        if (mandate.status == Status.None) revert MandateNotFound(issuer, mandateHash);
        if (mandate.status == Status.Revoked) {
            revert MandateNotActive(issuer, mandateHash, Status.Revoked);
        }
        if (mandate.status == Status.Consumed) {
            revert MandateNotActive(issuer, mandateHash, Status.Consumed);
        }

        mandate.status = Status.Revoked;
        emit MandateStatusChanged(issuer, mandateHash, Status.Revoked, msg.sender, mandate.expiresAt);
    }

    /// @inheritdoc ITPALedger
    function isValid(address issuer, bytes32 mandateHash) public view returns (bool) {
        _validateNamespace(issuer, mandateHash);
        Mandate storage mandate = _mandates[issuer][mandateHash];
        return mandate.status == Status.Active && block.timestamp < mandate.expiresAt;
    }

    /// @inheritdoc ITPALedger
    function getMandate(address issuer, bytes32 mandateHash)
        external
        view
        returns (Status storedStatus, Status effectiveStatus, uint64 expiresAt)
    {
        _validateNamespace(issuer, mandateHash);
        Mandate storage mandate = _mandates[issuer][mandateHash];
        storedStatus = mandate.status;
        expiresAt = mandate.expiresAt;
        effectiveStatus = _effectiveStatus(mandate);
    }

    /// @inheritdoc ITPALedger
    function mandateKey(address issuer, bytes32 mandateHash) external pure returns (bytes32) {
        _validateNamespace(issuer, mandateHash);
        return keccak256(abi.encode(issuer, mandateHash));
    }

    function _validateNamespace(address issuer, bytes32 mandateHash) private pure {
        if (issuer == address(0)) revert ZeroIssuer();
        if (mandateHash == bytes32(0)) revert ZeroMandateHash();
    }

    function _requireActiveAndUnexpired(address issuer, bytes32 mandateHash, Mandate storage mandate)
        private
        view
    {
        if (mandate.status == Status.None) revert MandateNotFound(issuer, mandateHash);
        if (mandate.status != Status.Active) {
            revert MandateNotActive(issuer, mandateHash, mandate.status);
        }
        if (block.timestamp >= mandate.expiresAt) {
            revert MandateExpired(issuer, mandateHash, mandate.expiresAt);
        }
    }

    function _effectiveStatus(Mandate storage mandate) private view returns (Status) {
        if (mandate.status == Status.Active && block.timestamp >= mandate.expiresAt) {
            return Status.Expired;
        }
        return mandate.status;
    }
}
