/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

/**
 * @file
 *   This file defines the API for application specific callbacks.
 */

#pragma once

class AppDelegate {
public:
	virtual ~AppDelegate()
	{
	}
	virtual void OnReceiveError()
	{
	};
	virtual void OnRendezvousStarted()
	{
	};
	virtual void OnRendezvousStopped()
	{
	};
};
