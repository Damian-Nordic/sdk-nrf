/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#pragma once

#include "AppEvent.h"
#include "BoltLockManager.h"

#include <platform/CHIPDeviceLayer.h>

struct k_timer;

class AppTask {
public:
	static constexpr size_t APP_EVENT_QUEUE_SIZE = 10;

	int StartApp();

	void PostEvent(const AppEvent& aEvent);
	void UpdateClusterState();

private:
	int Init();

	void DispatchEvent(const AppEvent& event);
	void LockActionHandler(BoltLockManager::Action action, bool chipInitiated);
	void CompleteLockActionHandler();
	void StartThreadHandler();
	void StartBLEAdvertisingHandler();

#ifdef CONFIG_CHIP_NFC_COMMISSIONING
	int StartNFCTag();
#endif

	static void ButtonEventHandler(uint32_t buttons_state, uint32_t has_changed);
	static void ThreadProvisioningHandler(const chip::DeviceLayer::ChipDeviceEvent *event, intptr_t arg);

	friend AppTask & GetAppTask();

	static AppTask sAppTask;
};

inline AppTask & GetAppTask()
{
	return AppTask::sAppTask;
}
