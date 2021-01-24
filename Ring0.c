//#include <windows.h>
#include <ntifs.h>
#include <wdm.h>

#define DEVICE_NAME L"\\Device\\Project1Dev"
#define DRIVER_LINK L"\\??\\MsgBoxAWatcherDriverLnk"

// 申请了4KB设备扩展内存，用于替代全局变量
// 0-3字节：调用门描述符地址（GDT）
// 4-7字节：中断门描述符地址（IDT）
#define DeviceExtendSize 0x1000

// 3环发 IRP_MJ_DEVICE_CONTROL 的操作编号
#define OPER_CALL_GATE_R0 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define OPER_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define OPER_GET_APICALLRECORD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define OPER_SET_PTE \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define OPER_GET_CALL_RECORD \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define OPER_SET_INT_GATE \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define OPER_SET_CALL_GATE \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 结构声明
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	UINT32 SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	UINT32 Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	UINT32 CheckSum;
	UINT32 TimeDateStamp;
	PVOID LoadedImports;
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

// API调用记录
typedef struct _APICALLRECORD
{
	LIST_ENTRY ApiCallRecordList; // 链表
	UINT32 pApiAddress;			  // API函数地址
	UINT32 nParam;				  // 参数个数
	UINT32 Param[32];			  // 参数列表
} APICALLRECORD, *PAPICALLRECORD;

// 全局变量
PDEVICE_OBJECT g_pDevObj = NULL; // 自定义设备，用于和3环通信

NTSTATUS IrpCreateProc(PDEVICE_OBJECT pDevObj, PIRP pIrp);
NTSTATUS IrpCloseProc(PDEVICE_OBJECT pDevObj, PIRP pIrp);
NTSTATUS IrpDeviceControlProc(PDEVICE_OBJECT pDevObj, PIRP pIrp);
VOID DriverUnload(PDRIVER_OBJECT pDriver);
ULONG *GetPDE(ULONG addr);
ULONG *GetPTE(ULONG addr);
void SetIntGate(PVOID pFunc);
void __stdcall User32ApiSpy(UINT32 ESP3, UINT32 EIP3);
void FreeApiCallQueue(IN PAPICALLRECORD QueueHead);
UINT32 GetCountApiCallQueue(IN PAPICALLRECORD QueueHead);
void PopApiCallQueue(IN PAPICALLRECORD QueueHead, OUT PAPICALLRECORD *pApiCallRecord);
void PushApiCallQueue(IN PAPICALLRECORD QueueHead, IN PAPICALLRECORD pApiCallRecord);
void InitApiCallQueue(IN PAPICALLRECORD QueueHead);

APICALLRECORD g_ApiCallRecordQueue = {0}; // API调用记录队列，不要直接操作该链表，使用程序提供的API

// User32.dll 导出函数的钩子函数
// 调用方式：修改API函数头2字节，使API函数触发中断，通过提权中断门调用本函数
void __declspec(naked) User32ApiSpyNaked()
{
	__asm
	{
		pushad; // esp - 0x20
		pushfd; // esp - 0x04

		mov eax, [esp + 0x24];
		mov ecx, [esp + 0x24 + 0x0C];

		//int 3
		push eax; // EIP3
		push ecx; // ESP3
		call User32ApiSpy;

		popfd;
		popad;
		iretd;
	}
}

// 此处需要完成的工作：读取3环EIP，判断API来源，读取3环ESP，获取参数，传给3环控制程序
void __stdcall User32ApiSpy(UINT32 ESP3, UINT32 EIP3)
{
	UINT32 ApiAddress;
	// EIP3-0x02是API的地址
	// ESP3是3环的ESP，可以用来读参数
	__asm push fs;

	ApiAddress = EIP3 - 2;
	//DbgPrint("ESP3: %08x, API: %08x\n", ESP3, ApiAddress);
	// 判断API地址
	if (ApiAddress == 0x77d507ea)
	{
		PAPICALLRECORD pApiCallRecord = NULL;
		// 添加调用记录到队列，监视进程通过IRP消息读取队列
		pApiCallRecord = (PAPICALLRECORD)ExAllocatePool(PagedPool, sizeof(APICALLRECORD));
		pApiCallRecord->nParam = 4;
		pApiCallRecord->pApiAddress = ApiAddress;
		pApiCallRecord->Param[0] = ((PUINT32)ESP3)[1];
		pApiCallRecord->Param[1] = ((PUINT32)ESP3)[2];
		pApiCallRecord->Param[2] = ((PUINT32)ESP3)[3];
		pApiCallRecord->Param[3] = ((PUINT32)ESP3)[4];
		DbgPrint("%x %x %x %x\r\n", ((PUINT32)ESP3)[1], ((PUINT32)ESP3)[2], ((PUINT32)ESP3)[3], ((PUINT32)ESP3)[4]);
		PushApiCallQueue(&g_ApiCallRecordQueue, (PAPICALLRECORD)pApiCallRecord);
	}
	__asm pop fs;
}

// 入口函数
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING RegPath)
{
	NTSTATUS status;
	ULONG uIndex = 0;
	PDEVICE_OBJECT pDeviceObj = NULL; // 设备对象指针
	UNICODE_STRING DeviceName;		  // 设备名，0环用
	UNICODE_STRING SymbolicLinkName;  // 符号链接名，3环用

	// 初始化调用记录队列
	//InitApiCallQueue(&g_ApiCallRecordQueue);

	// 创建设备名称
	RtlInitUnicodeString(&DeviceName, DEVICE_NAME);
	// 创建设备
	status = IoCreateDevice(pDriver, DeviceExtendSize, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObj);
	if (status != STATUS_SUCCESS)
	{
		IoDeleteDevice(pDeviceObj);
		DbgPrint("创建设备失败.\n");
		return status;
	}
	// 全局变量依赖于设备扩展内存
	// 初始化全局设备指针
	g_pDevObj = pDeviceObj;
	// 初始化设备扩展数据
	memset(pDeviceObj->DeviceExtension, 0, DeviceExtendSize);
	//DbgPrint("创建设备成功.\n");
	// 设置交互数据的方式
	pDeviceObj->Flags |= DO_BUFFERED_IO;
	// 创建符号链接
	RtlInitUnicodeString(&SymbolicLinkName, DRIVER_LINK);
	IoCreateSymbolicLink(&SymbolicLinkName, &DeviceName);
	// 设置分发函数
	pDriver->MajorFunction[IRP_MJ_CREATE] = IrpCreateProc;
	pDriver->MajorFunction[IRP_MJ_CLOSE] = IrpCloseProc;
	pDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceControlProc;

	// 初始化调用记录队列
	InitApiCallQueue(&g_ApiCallRecordQueue);

	// 设置卸载函数
	pDriver->DriverUnload = DriverUnload;

	DbgPrint("测试\r\n");

	return STATUS_SUCCESS;
}

// IRP_MJ_DEVICE_CONTROL 处理函数
NTSTATUS IrpDeviceControlProc(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	PIO_STACK_LOCATION pIrpStack;
	ULONG uIoControlCode;
	PVOID pIoBuffer;
	ULONG uInLength;
	ULONG uOutLength;
	ULONG t, lo, hi;

	// 获取IRP数据
	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	// 获取控制码
	uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	// 获取缓冲区地址（输入输出是同一个）
	pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;
	// Ring3 发送数据的长度
	uInLength = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	// Ring0 发送数据的长度
	uOutLength = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;

	switch (uIoControlCode)
	{
	case OPER_GET_CALL_RECORD:
		PAPICALLRECORD record = NULL;
		PopApiCallQueue(&g_ApiCallRecordQueue, &record);
		if (record == NULL)
		{
			// 设置状态，返回数据
			pIrp->IoStatus.Information = 0; // 返回给3环的数据量
			status = STATUS_SUCCESS;
		}
		else
		{
			memcpy(pIoBuffer, record, sizeof(APICALLRECORD));
			// 设置状态，返回数据
			pIrp->IoStatus.Information = sizeof(APICALLRECORD); // 返回给3环的数据量
			status = STATUS_SUCCESS;
		}
		break;
	case OPER_SET_INT_GATE:
		SetIntGate(User32ApiSpyNaked);
		pIrp->IoStatus.Information = 0; // 返回给3环的数据量
		status = STATUS_SUCCESS;
		break;
	case OPER_SET_CALL_GATE:
		//__asm int 3
		RtlMoveMemory(&t, pIoBuffer, uInLength);
		lo = t & 0x0000ffff;
		hi = t & 0xffff0000;
		*((PULONG)0x8003f048) = 0x00080000 | lo;
		*((PULONG)0x8003f04c) = 0x0000ec03 | hi;
		pIrp->IoStatus.Information = 0; // 返回给3环的数据量
		status = STATUS_SUCCESS;
	}

	// 返回状态如果不设置，Ring3返回值是失败
	pIrp->IoStatus.Status = status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

void SetIntGate(PVOID pFunc)
{
	// TODO:这里要找到第一个空的
	// 构造中断门描述符
	ULONG IntGateLo = (((ULONG)pFunc & 0x0000FFFF) | 0x00080000);
	ULONG IntGateHi = (((ULONG)pFunc & 0xFFFF0000) | 0x0000EE00);

	*((PULONG)0x8003f500) = IntGateLo;
	*((PULONG)0x8003f504) = IntGateHi;
}

// 不设置这个函数，则Ring3调用CreateFile会返回1
// IRP_MJ_CREATE 处理函数
NTSTATUS IrpCreateProc(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	//DbgPrint("应用层连接设备.\n");
	// 返回状态如果不设置，Ring3返回值是失败
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

// IRP_MJ_CLOSE 处理函数
NTSTATUS IrpCloseProc(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	//DbgPrint("应用层断开连接设备.\n");
	// 返回状态如果不设置，Ring3返回值是失败
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

// 卸载驱动
VOID DriverUnload(PDRIVER_OBJECT pDriver)
{
	UNICODE_STRING SymbolicLinkName;

	// 删除符号链接，删除设备
	RtlInitUnicodeString(&SymbolicLinkName, DRIVER_LINK);
	IoDeleteSymbolicLink(&SymbolicLinkName);
	IoDeleteDevice(pDriver->DeviceObject);
	DbgPrint("驱动卸载成功\n");
}

// 获取PDE
ULONG *GetPDE(ULONG addr)
{
	return (ULONG *)(0xc0600000 + ((addr >> 18) & 0x3ff8));
}

// 获取PTE
ULONG *GetPTE(ULONG addr)
{
	return (ULONG *)(0xc0000000 + ((addr >> 9) & 0x7ffff8));
}

// 初始化队列
void InitApiCallQueue(IN PAPICALLRECORD QueueHead)
{
	QueueHead->ApiCallRecordList.Flink = QueueHead->ApiCallRecordList.Blink = (PLIST_ENTRY)QueueHead;
}

// 插入一条调用记录到队尾
void PushApiCallQueue(IN PAPICALLRECORD QueueHead, IN PAPICALLRECORD pApiCallRecord)
{
	// 原队尾的下一个节点指向新队尾
	QueueHead->ApiCallRecordList.Blink->Flink = (PLIST_ENTRY)pApiCallRecord;
	// 新队尾的上一个节点指向原队尾
	pApiCallRecord->ApiCallRecordList.Blink = QueueHead->ApiCallRecordList.Blink;
	// 新队尾的下一个节点指向队列头
	pApiCallRecord->ApiCallRecordList.Flink = (PLIST_ENTRY)QueueHead;
	// 队列头的上一个节点指向新队尾
	QueueHead->ApiCallRecordList.Blink = (PLIST_ENTRY)pApiCallRecord;
}

// 从队首弹出一条调用记录
void PopApiCallQueue(IN PAPICALLRECORD QueueHead, OUT PAPICALLRECORD *pApiCallRecord)
{
	// 记录要弹出的节点
	*pApiCallRecord = (PAPICALLRECORD)(QueueHead->ApiCallRecordList.Flink);
	// 如果队列为空，返回NULL
	if (*pApiCallRecord == &g_ApiCallRecordQueue)
	{
		*pApiCallRecord = NULL;
	}
	// 第二个节点的上一个节点指向队首
	QueueHead->ApiCallRecordList.Flink->Flink->Blink = (PLIST_ENTRY)QueueHead;
	// 队首的下一个节点指向第二个节点
	QueueHead->ApiCallRecordList.Flink = QueueHead->ApiCallRecordList.Flink->Flink;
}

// 计算队列长度
UINT32 GetCountApiCallQueue(IN PAPICALLRECORD QueueHead)
{
	UINT32 cnt = 0;
	PLIST_ENTRY pList = QueueHead->ApiCallRecordList.Flink;
	while (pList != (PLIST_ENTRY)QueueHead)
	{
		pList = pList->Flink;
		cnt++;
	}
	return cnt;
}

// 释放队列内存
void FreeApiCallQueue(IN PAPICALLRECORD QueueHead)
{
	PAPICALLRECORD pApiCallRecord;
	while (QueueHead->ApiCallRecordList.Flink != (PLIST_ENTRY)QueueHead)
	{
		PopApiCallQueue(QueueHead, &pApiCallRecord);
		ExFreePool(pApiCallRecord);
	}
}