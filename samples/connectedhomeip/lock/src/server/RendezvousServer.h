/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#pragma once

#include "AppDelegate.h"
#include <platform/CHIPDeviceLayer.h>
#include <transport/RendezvousSession.h>

namespace chip {

class RendezvousServer : public RendezvousSessionDelegate {
public:
	RendezvousServer();

	CHIP_ERROR Init(const RendezvousParameters & params, TransportMgrBase *transportMgr);
	void SetDelegate(AppDelegate *delegate)
	{
		mDelegate = delegate;
	};

//////////////// RendezvousSessionDelegate Implementation ///////////////////

	void OnRendezvousConnectionOpened() override;
	void OnRendezvousConnectionClosed() override;
	void OnRendezvousError(CHIP_ERROR err) override;
	void OnRendezvousMessageReceived(const PacketHeader & packetHeader, const Transport::PeerAddress & peerAddress,
					 System::PacketBufferHandle buffer) override;
	void OnRendezvousComplete() override;
	void OnRendezvousStatusUpdate(Status status, CHIP_ERROR err) override;
	RendezvousSession *GetRendezvousSession()
	{
		return &mRendezvousSession;
	};

private:
	RendezvousSession mRendezvousSession;
	AppDelegate *mDelegate;
};

} // namespace chip
