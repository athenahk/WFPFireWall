#include<iostream>
#include<vector>
#include<windows.h>
#include<fwpmu.h>
#include<winsock.h>
#include"WFPFireWallRing3.h"
#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "ws2_32.lib")
HANDLE g_Handle;
std::vector<GUID> vecGuid;
std::vector<UINT64> vecId;
bool AddSubLayer(UINT16 weight)
{
	DWORD errCode = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &g_Handle);
	if (errCode != ERROR_SUCCESS)
	{
		std::cout << "FirewallEngine : Failed to open WFP Engine. errcode:" << errCode;
		return false;
	}

	FWPM_SUBLAYER sublayer = { 0 };
	sublayer.displayData.name = const_cast<wchar_t*>(L"Wojtek's WFPFirewall Sublayer");
	sublayer.displayData.description = const_cast<wchar_t*>(L"Container for filters added by Wojtek's WFPFirewall");
	sublayer.subLayerKey = FIREWALL_ENGINE_SUBLAYER_KEY;
	vecGuid.push_back(sublayer.subLayerKey);
	sublayer.weight = weight;
	sublayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
	errCode = FwpmSubLayerAdd(g_Handle, &sublayer, NULL);
	if (errCode != ERROR_SUCCESS)
	{
		std::cout << "FirewallEngine: Failed to add layer. errcode: %x\n" << errCode;
		FwpmEngineClose(g_Handle);
		return false;
	}
	return true;
}

void freeResource()
{
	for (int i = 0; i < vecId.size(); i++)
	{
		if (vecId[i] != 0)
		{
			FwpmFilterDeleteById(g_Handle, vecId[i]);
			vecId[i] = 0;
		}
	}
	for (int i = 0; i < vecGuid.size(); i++)
	{
		if (vecGuid[i].Data1 != 0) {
			DWORD error = FwpmSubLayerDeleteByKey(g_Handle, (const GUID*)&vecGuid[i]);
			std::cout << "delete Sublayer:" << error;
			memset(&vecGuid[i], 0, sizeof(GUID));
		}
	}
	FwpmEngineClose(g_Handle);
}

bool AddFilter(UINT32 ip, UINT32 mask, bool limit, GUID conFieldKey, UINT16 port)
{
	FWP_V4_ADDR_AND_MASK addrMask = { 0 };

	FWPM_FILTER_CONDITION condition = { 0 };
	condition.matchType = FWP_MATCH_EQUAL;
	//FWPM_CONDITION_IP_REMOTE_ADDRESS
	condition.fieldKey = conFieldKey;

	FWPM_FILTER	filter = { 0 };

	if (condition.fieldKey == FWPM_CONDITION_IP_REMOTE_ADDRESS)
	{
		condition.conditionValue.type = FWP_V4_ADDR_MASK;
		condition.conditionValue.v4AddrMask = &addrMask;
		addrMask.addr = htonl(ip);
		addrMask.mask = mask;

	}
	else if (condition.fieldKey == FWPM_CONDITION_IP_SOURCE_PORT)
	{
		condition.conditionValue.type = FWP_UINT16;
		condition.conditionValue.uint16 = port;
	}
	else if (condition.fieldKey == FWPM_CONDITION_IP_REMOTE_PORT)
	{
		condition.conditionValue.type = FWP_UINT16;
		condition.conditionValue.uint16 = port;
	}
	//FWPM_LAYER_INBOUND_TRANSPORT_V4
	filter.layerKey = FWPM_LAYER_INBOUND_TRANSPORT_V4;
	filter.subLayerKey = FIREWALL_ENGINE_SUBLAYER_KEY;
	filter.weight.type = FWP_EMPTY;
	filter.numFilterConditions = 1;
	filter.filterCondition = &condition;
	filter.flags = FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED;
	filter.displayData.description = const_cast<wchar_t*>(L"Wojtek's WFPFirewall inbound data limit filter");
	filter.displayData.name = const_cast<wchar_t*>(L"Limit data you can download");

	filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
	filter.action.calloutKey = FIREWALL_ENGINE_CALLOUT_DATA_LIMIT_KEY;
	filter.rawContext = limit;
	UINT64 filterId = 0;
	DWORD errCode = FwpmFilterAdd(g_Handle, &filter, NULL, &filterId);
	vecId.push_back(filterId);
	if (errCode != ERROR_SUCCESS)
	{
		std::cout << "Failed to Add Filter:" << errCode << std::endl;
		return false;
	}
	return true;
}
int main()
{
	std::string ip;
	int choice;
	UINT32 mask;
	UINT16 port;
	bool isBreak = 0;
	AddSubLayer(100);
	while (1) {
		std::cout << "please input ip:";
		std::cin >> ip;
		std::cout << "please input mask:";
		std::cin.unsetf(std::ios::dec);
		std::cin.setf(std::ios::hex);
		std::cin >> mask;
		std::cin.unsetf(std::ios::hex);
		std::cin.setf(std::ios::dec);
		std::cout << "condition.fieldKey:\n1.FWPM_CONDITION_IP_REMOTE_ADDRESS\n2.FWPM_CONDITION_IP_SOURCE_PORT\n3.FWPM_CONDITION_IP_DESTINATION_PORT\nplease choice:" << std::endl;
		GUID fieldKey;
		std::cin >> choice;
		switch (choice)
		{
		case 1:
			fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
			break;
		case 2:
			fieldKey = FWPM_CONDITION_IP_SOURCE_PORT;
			break;
		case 3:
			fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
			break;
		default:
			std::cout << "error choice!\n";
			isBreak = 1;
		}
		if (isBreak)
			break;
		std::cout << "please input port:";
		std::cin >> port;
		AddFilter(inet_addr(ip.c_str()), mask, 1, fieldKey, port);
		system("pause");
	}
	freeResource();
	system("pause");
}