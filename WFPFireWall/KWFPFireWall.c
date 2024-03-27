#include<ntddk.h>
#define NDIS61 1
#include"KWFPFireWall.h"
#define DEBUG 1

#ifndef DEBUG
#define LOG(message) \
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s\n", message);
#define LOG_STATUS(message, status) \
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s: %s (0x%08x)\n", (NT_SUCCESS(status) ? "OK" : "ERRPR"), message, status);
#else
#define LOG(message)   KdPrint((message))
#define LOG_STATUS(message, status) KdPrint(("%s : %x\n", message, status))
#endif
#define MAX_FILTER 30


UINT32 calloutId;
HANDLE g_EngineHandle;
PDEVICE_OBJECT g_DevObj;
VOID DriverUnload(PDRIVER_OBJECT pDriver)
{	
	FwpsCalloutUnregisterById(calloutId);
	FwpmCalloutDeleteByKey(g_EngineHandle, &FIREWALL_ENGINE_CALLOUT_DATA_LIMIT_KEY);
	FwpmEngineClose(g_EngineHandle);
	IoDeleteDevice(g_DevObj);
}
struct filterInf {
	UINT64 filterId;
	BOOL limit;
};

struct filterInf filterinf[MAX_FILTER];

VOID GetNetBufferData(
	PNET_BUFFER                NetBuffer,
	PUCHAR                        OutputBuffer,
	ULONG                        OutputBufferSize,
	PULONG                        OutputBytesCopied
)
{

	PMDL        Mdl = NetBuffer->CurrentMdl;
	*OutputBytesCopied = 0;

	if (NetBuffer->DataLength > OutputBufferSize)
	{

		DbgPrint("Not enough output buffer space, in: %d, out : %d\n",
			NetBuffer->DataLength,
			OutputBufferSize);


		return;
	}

	NdisMoveMemory(OutputBuffer,
		(PUCHAR)MmGetSystemAddressForMdlSafe(Mdl, LowPagePriority) + NetBuffer->CurrentMdlOffset,
		Mdl->ByteCount - NetBuffer->CurrentMdlOffset);


	OutputBuffer += Mdl->ByteCount - NetBuffer->CurrentMdlOffset;
	*OutputBytesCopied += Mdl->ByteCount - NetBuffer->CurrentMdlOffset;

	//
	//循环 MDL链表，获取每一个结点的数据，数据被保存到 OutputBuffer里面
	//OutputBuffer的空间不断地扩大。

	//当链表不为空， 并且 OutputBuffer的长度 < 1个NET_BUFFER的总长度

	while (((Mdl = Mdl->Next) != NULL) && (*OutputBytesCopied < NetBuffer->DataLength))
	{
		NdisMoveMemory(OutputBuffer,
			MmGetSystemAddressForMdlSafe(Mdl, LowPagePriority),
			Mdl->ByteCount);

		OutputBuffer += Mdl->ByteCount;          //数据被保存到 OutputBuffer里面
		*OutputBytesCopied += Mdl->ByteCount;    //OutputBuffer的空间不断地扩大
	}

	if (Mdl != NULL)
	{
		NdisMoveMemory(OutputBuffer,
			MmGetSystemAddressForMdlSafe(Mdl, LowPagePriority),
			NetBuffer->DataLength);

		OutputBuffer += Mdl->ByteCount;
		*OutputBytesCopied += Mdl->ByteCount;
	}
	DbgPrint("buffer copied: %d bytes\n", *OutputBytesCopied);
}
void classFn(
	_In_ const FWPS_INCOMING_VALUES0* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_opt_ const void* classifyContext,
	_In_ const FWPS_FILTER3* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT0* classifyOut
)
{
	UCHAR context[1000] = { 0 };
	ULONG writeBytes = 0;
	GetNetBufferData(((PNET_BUFFER_LIST)layerData)->FirstNetBuffer, context, 1000, &writeBytes);
	for (int i = 0; i < writeBytes; i++)
	{
		KdPrint(("%02x", context[i]));
		if (i % 15 == 0)
			KdPrint(("\n"));
	}
	KdPrint(("\n"));
	classifyOut->actionType = FWP_ACTION_PERMIT;
	for (int i = 0; i < MAX_FILTER; i++)
	{
		if (filter->filterId == filterinf[i].filterId
			&& filterinf[i].limit) {
			classifyOut->actionType = FWP_ACTION_PERMIT;
			break;
		}
	}
}

NTSTATUS NotifyFn(
	_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID* filterKey,
	_Inout_ FWPS_FILTER3* filter
	)
{
	switch (notifyType)
	{
	case FWPS_CALLOUT_NOTIFY_ADD_FILTER:
	{
		for (int i = 0; i < MAX_FILTER; i++)
		{
			if (!filterinf[i].filterId)
			{
				filterinf[i].filterId = filter->filterId;
				filterinf[i].limit = filter->context;
				return STATUS_SUCCESS;
			}
		}
		LOG("Too many filter set, no free space!\n");
		break;
	}
	case FWPS_CALLOUT_NOTIFY_DELETE_FILTER:
	{
		for (int i = 0; i < MAX_FILTER; i++)
		{
			if (filterinf[i].filterId == filter->filterId)
			{
				filterinf[i].filterId = 0;
				break;
			}
		}
		break;
	}
	}
	return STATUS_SUCCESS;
}

void (deleteFn)(
	_In_ UINT16 layerId,
	_In_ UINT32 calloutId,
	_In_ UINT64 flowContext
	)
{

}


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg)
{
	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\WfpFireWall");
	UNICODE_STRING symbolName = RTL_CONSTANT_STRING(L"\\??\\WfpFireWall");
	NTSTATUS status = IoCreateDevice(pDriver, 0, &devName, FILE_DEVICE_NETWORK, 0, FALSE, &g_DevObj);
	LOG_STATUS("Create Device Success!\n", status);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//status = IoCreateSymbolicLink(&symbolName, &devName);
	//LOG_STATUS("Create SymbolName SUCCESS!\n", status);
	//if (!NT_SUCCESS(status))
	//{
	//	return status;
	//}
	
	status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &g_EngineHandle);
	LOG_STATUS("Open Engine Success!\n", status);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	FWPS_CALLOUT calloutRegister = {
		.calloutKey = FIREWALL_ENGINE_CALLOUT_DATA_LIMIT_KEY,
		.flags = 0,
		.classifyFn = classFn,
		.notifyFn = NotifyFn,
		.flowDeleteFn = deleteFn,
	};

	status = FwpsCalloutRegister(g_DevObj, &calloutRegister, &calloutId);
	FWPM_CALLOUT callOutAdd = {
		.calloutKey = FIREWALL_ENGINE_CALLOUT_DATA_LIMIT_KEY,
		.flags = 0,
		.applicableLayer = FWPM_LAYER_INBOUND_TRANSPORT_V4,
		.calloutId = calloutId,
		.displayData = {
			.description = L"Callout used for limiting data transfered to certain hosts:ports",
			.name = L"Wojtek's WFPFirewall Data Limit Callout",
}
	};
	status = FwpmCalloutAdd(g_EngineHandle, &callOutAdd, NULL, NULL);
	LOG_STATUS("add outbound callout to filter engine", status);

	pDriver->DriverUnload = DriverUnload;
	return status;
}