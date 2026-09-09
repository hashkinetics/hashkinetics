// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title DailyLimit — a per-UTC-day allowance for the attested direction (unlock / mint).
/// @notice A compromised attestor threshold can move at most `dailyCap` per day before a pause lands.
///         The service queues what does not fit and drains it the next day.
abstract contract DailyLimit {
    uint256 public dailyCap;
    uint256 public dayIndex;
    uint256 public usedToday;

    event DailyCapSet(uint256 dailyCap);

    error DailyCapExceeded(uint256 requested, uint256 remaining);

    function _initDailyCap(uint256 cap) internal {
        dailyCap = cap;
        emit DailyCapSet(cap);
    }

    function _setDailyCap(uint256 cap) internal {
        dailyCap = cap;
        emit DailyCapSet(cap);
    }

    /// @notice How much can still pass today (UTC day = block.timestamp / 1 days).
    function remainingToday() public view returns (uint256) {
        uint256 day = block.timestamp / 1 days;
        uint256 used = day == dayIndex ? usedToday : 0;
        return used >= dailyCap ? 0 : dailyCap - used;
    }

    function _consumeDaily(uint256 amount) internal {
        uint256 day = block.timestamp / 1 days;
        if (day != dayIndex) {
            dayIndex = day;
            usedToday = 0;
        }
        uint256 remaining = usedToday >= dailyCap ? 0 : dailyCap - usedToday;
        if (amount > remaining) revert DailyCapExceeded(amount, remaining);
        usedToday += amount;
    }
}
