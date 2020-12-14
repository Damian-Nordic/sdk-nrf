/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#pragma once

#include <cstdint>

#include "AppEvent.h"

struct k_timer;

class BoltLockManager {
public:
	enum class Action : uint8_t {
		Lock,
		Unlock
	};

	void Init();

	bool IsUnlocked();
	bool IsActionInProgress();

	bool InitiateAction(Action action, bool chipInitiated);
	bool CompleteCurrentAction(bool& chipInitiated);

private:
	enum class State : uint8_t {
		LockingInitiated = 0,
		LockingCompleted,
		UnlockingInitiated,
		UnlockingCompleted
	};

	static constexpr uint32_t ACTUATOR_MOVEMENT_PERIOS_MS = 2000;

	void StartTimer(uint32_t aTimeoutMs);
	void CancelTimer();

	static void ActuatorTimerHandler(k_timer *timer);

	friend BoltLockManager & BoltLockMgr();

	State mState;
	bool mChipInitiatedAction;

	static BoltLockManager sLock;
};

inline BoltLockManager & BoltLockMgr()
{
	return BoltLockManager::sLock;
}
