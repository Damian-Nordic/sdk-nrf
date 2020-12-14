/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include "RendezvousServer.h"

#include "SessionManager.h"
#include <core/CHIPError.h>
#include <support/CodeUtils.h>
#include <transport/SecureSessionMgr.h>

#if CHIP_ENABLE_OPENTHREAD
#include <platform/ThreadStackManager.h>
#endif
#include <lib/mdns/DiscoveryManager.h>

using namespace ::chip::Inet;
using namespace ::chip::Transport;
using namespace ::chip::DeviceLayer;

namespace chip {

RendezvousServer::RendezvousServer() : mRendezvousSession(this)
{
}

CHIP_ERROR RendezvousServer::Init(const RendezvousParameters & params, TransportMgrBase *transportMgr)
{
	return mRendezvousSession.Init(params, transportMgr);
}

void RendezvousServer::OnRendezvousError(CHIP_ERROR err)
{
	ChipLogProgress(AppServer, "OnRendezvousError: %s", ErrorStr(err));
}

void RendezvousServer::OnRendezvousConnectionOpened()
{
	ChipLogProgress(AppServer, "OnRendezvousConnectionOpened");
}

void RendezvousServer::OnRendezvousConnectionClosed()
{
	ChipLogProgress(AppServer, "OnRendezvousConnectionClosed");
}

void RendezvousServer::OnRendezvousMessageReceived(const PacketHeader & packetHeader, const PeerAddress & peerAddress,
						   System::PacketBufferHandle buffer)
{
}

void RendezvousServer::OnRendezvousComplete()
{
	ChipLogProgress(AppServer, "Device completed Rendezvous process");
	if (mRendezvousSession.GetRemoteNodeId().HasValue()) {
		SessionManager().NewPairing(Optional<Transport::PeerAddress>{}, mRendezvousSession.GetRemoteNodeId().Value(),
					    &mRendezvousSession.GetPairingSession());
	} else {
		ChipLogError(AppServer, "Commissioner did not assign a node ID to the device!!!");
	}
}

void RendezvousServer::OnRendezvousStatusUpdate(Status status, CHIP_ERROR err)
{
	VerifyOrExit(err == CHIP_NO_ERROR, ChipLogError(AppServer, "OnRendezvousStatusUpdate: %s", chip::ErrorStr(err)));

	switch (status) {
	case RendezvousSessionDelegate::SecurePairingSuccess:
		ChipLogProgress(AppServer, "Device completed SPAKE2+ handshake");
		if (mDelegate != nullptr) {
			mDelegate->OnRendezvousStarted();
		}
		break;

	case RendezvousSessionDelegate::SecurePairingFailed:
		ChipLogProgress(AppServer, "Failed in SPAKE2+ handshake");
		if (mDelegate != nullptr) {
			mDelegate->OnRendezvousStopped();
		}
		break;

	case RendezvousSessionDelegate::NetworkProvisioningSuccess:
		ChipLogProgress(AppServer, "Device was assigned network credentials");
		chip::Mdns::DiscoveryManager::GetInstance().StartPublishDevice();
		if (mDelegate != nullptr) {
			mDelegate->OnRendezvousStopped();
		}
		break;

	case RendezvousSessionDelegate::NetworkProvisioningFailed:
		ChipLogProgress(AppServer, "Failed in network provisioning");
		if (mDelegate != nullptr) {
			mDelegate->OnRendezvousStopped();
		}
		break;

	default:
		break;
	}
	;

exit:
	return;
}
} // namespace chip
