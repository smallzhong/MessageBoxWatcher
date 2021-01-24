#include "StdAfx.h"
#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <winioctl.h>

using namespace std;

DWORD *GetPDE(DWORD addr);
DWORD *GetPTE(DWORD addr);
DWORD u_t, u_pde, u_pte;
DWORD t, pde, pte;
DWORD dwRetBytes; // 返回的字节数

typedef struct _APICALLRECORD
{
	LIST_ENTRY ApiCallRecordList; // 链表
	UINT32 pApiAddress;			  // API函数地址
	UINT32 nParam;				  // 参数个数
	UINT32 Param[32];			  // 参数列表
} APICALLRECORD, *PAPICALLRECORD;

#define DRIVER_NAME L"Project1"
#define DRIVER_PATH L"Project1.sys"
#define DRIVER_LINK L"\\\\.\\MsgBoxAWatcherDriverLnk"

#define OPER_GET_CALL_RECORD \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define OPER_SET_INT_GATE \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define OPER_SET_CALL_GATE \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define EXIT_ERROR(x)                                 \
	do                                                \
	{                                                 \
		cout << "error in line " << __LINE__ << endl; \
		cout << x;                                    \
		getchar();                                    \
		exit(EXIT_FAILURE);                           \
	} while (0)

BOOL LoadDriver(PCWSTR lpszDriverName, PCWSTR lpszDriverPath);
void UpdateApiCallRecord();
void UnLoadDriver(PCWSTR lpszDriverName);

void __declspec(naked) setPTE()
{
	__asm {			
		pushad
		pushfd

				// pushad 和 pushfd 使ESP减小了 0x24 个字节
				// 原ESP+8就是参数1，+C就是参数2，+10就是参数3，详见堆栈图
				// 如果这里还有疑问，可以在windbg的内存窗口中观察

		mov eax,[esp+0x24+0x8+0x8] // 参数3
		mov dword ptr ds:[u_pte],eax
		or dword ptr [eax],0x00000006;

		mov eax,[esp+0x24+0x8+0x4] // 参数2
		mov dword ptr ds:[u_pde],eax
		or dword ptr [eax],0x00000006;

		mov eax,[esp+0x24+0x8+0x0] // 参数1
		mov dword ptr ds:[u_t],eax

		popfd
		popad

		
		retf 0xC // 注意堆栈平衡，写错蓝屏
	}
}

int main()
{
	// 加载驱动
	if (!LoadDriver(DRIVER_NAME, DRIVER_PATH))
	{
		EXIT_ERROR("驱动服务加载失败！");
	}

	printf("驱动服务加载成功！\n");

	// MessageBoxA 挂物理页，不这样操作，MessageBoxA的PTE可能是无效的
	__asm {
		mov eax, dword ptr ds:[MessageBoxA];
		mov eax,[eax];
	}

	t = (DWORD)MessageBox;

	pde = (DWORD)GetPDE(t);
	pte = (DWORD)GetPTE(t);

	// printf("t = %x pde = %x pte = %x\n", t, pde, pte);

	// 提权带参调用门，设置pte和pde的RW和US
	// printf("eq 8003f048 %04xEC03`0008%04x", (DWORD)setPTE >> 16, (DWORD)setPTE & 0xffff);
	BYTE t_inbuffer[123];
	memset(t_inbuffer, 0, sizeof t_inbuffer);
	t = (DWORD)setPTE;
	memcpy(&t_inbuffer, &t, sizeof(DWORD));

	HANDLE hDevice = CreateFileW(DRIVER_LINK, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (DeviceIoControl(hDevice, OPER_SET_CALL_GATE, t_inbuffer, sizeof(DWORD), NULL, 0, &dwRetBytes, NULL) == 0)
	{
		printf("error = %d\n", GetLastError());
		CloseHandle(hDevice);
		EXIT_ERROR("与驱动通信出错");
	}
	CloseHandle(hDevice);
	printf("调用门设置成功！\n");

	BYTE buff[6] = {0, 0, 0, 0, 0x48, 0};
	__asm
		{
		push pte
		push pde
		push t
		call fword ptr [buff] // 长调用，使用调用门提权
		}

	printf("PTE PDE属性修改成功！\n");

	// 设置中断门
	hDevice = CreateFileW(DRIVER_LINK, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (DeviceIoControl(hDevice, OPER_SET_INT_GATE, NULL, 0, NULL, 0, &dwRetBytes, NULL) == 0)
	{
		printf("error = %d\n", GetLastError());
		EXIT_ERROR("与驱动通信出错！");
		CloseHandle(hDevice);
	}
	CloseHandle(hDevice);
	printf("中断门设置成功！\n");

	// PATCH掉messagebox
	USHORT IntNumber = 0x20; // TODO:通过驱动获取当前第一个空着的中断
	USHORT hardcode = (IntNumber << 8) | 0xcd;
	*(PWORD)MessageBox = hardcode; // int 0x20

	printf("hook成功！\n以下为messagebox调用记录，按Q退出并解除钩子\r\n");
	// TODO: 这里可以加入和驱动通信把GDT,IDT表里面的东西改回来

	// 不断获取调用记录
	UpdateApiCallRecord();

	__asm {
		mov eax, dword ptr ds:[MessageBoxA];
		mov eax,[eax];
	}
	*(PWORD)MessageBox = 0xff8b; // 恢复
	UnLoadDriver(DRIVER_NAME);	 // 卸载驱动

	getchar();

	return 0;
}

// 从驱动获取调用记录
void UpdateApiCallRecord()
{
	HANDLE hDevice = CreateFileW(DRIVER_LINK, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("打开设备失败.\n");
		return;
	}
	APICALLRECORD ApiCallRecord;
	while (!GetAsyncKeyState('Q')) // 当一直按着Q的时候
	{
		Sleep(50);
		DeviceIoControl(hDevice, OPER_GET_CALL_RECORD, NULL, 0, &ApiCallRecord, sizeof(ApiCallRecord), &dwRetBytes, NULL);
		if (dwRetBytes == 0)
		{
			//printf("无API调用记录.\n");
			continue;
		}
		if (ApiCallRecord.pApiAddress == (DWORD)MessageBoxA)
		{
			printf("MessageBoxA(%x, %x, %x, %x);\n",
				   ApiCallRecord.Param[0], ApiCallRecord.Param[1], ApiCallRecord.Param[2], ApiCallRecord.Param[3]);
		}
	}
	CloseHandle(hDevice);
}

// 获取PDE
DWORD *GetPDE(DWORD addr)
{
	return (DWORD *)(0xc0600000 + ((addr >> 18) & 0x3ff8));
}

// 获取PTE
DWORD *GetPTE(DWORD addr)
{
	return (DWORD *)(0xc0000000 + ((addr >> 9) & 0x7ffff8));
}

// 加载驱动
BOOL LoadDriver(PCWSTR lpszDriverName, PCWSTR lpszDriverPath)
{
	// 获取驱动完整路径
	WCHAR szDriverFullPath[MAX_PATH] = {0};
	GetFullPathNameW(lpszDriverPath, MAX_PATH, szDriverFullPath, NULL);
	//printf("%s\n", szDriverFullPath);
	// 打开服务控制管理器
	SC_HANDLE hServiceMgr = NULL; // SCM管理器句柄
	hServiceMgr = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL == hServiceMgr)
	{
		printf("OpenSCManagerW 失败, %d\n", GetLastError());
		return FALSE;
	}
	//printf("打开服务控制管理器成功.\n");
	// 创建驱动服务
	SC_HANDLE hServiceDDK = NULL; // NT驱动程序服务句柄
	hServiceDDK = CreateServiceW(
		hServiceMgr,
		lpszDriverName,
		lpszDriverName,
		SERVICE_ALL_ACCESS,
		SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_IGNORE,
		szDriverFullPath,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL);
	if (NULL == hServiceDDK)
	{
		DWORD dwErr = GetLastError();
		if (dwErr != ERROR_IO_PENDING && dwErr != ERROR_SERVICE_EXISTS)
		{
			printf("创建驱动服务失败, %d\n", dwErr);
			return FALSE;
		}
	}
	//printf("创建驱动服务成功.\n");
	// 驱动服务已经创建，打开服务
	hServiceDDK = OpenServiceW(hServiceMgr, lpszDriverName, SERVICE_ALL_ACCESS);
	if (!StartService(hServiceDDK, NULL, NULL))
	{
		DWORD dwErr = GetLastError();
		if (dwErr != ERROR_SERVICE_ALREADY_RUNNING)
		{
			printf("运行驱动服务失败, %d\n", dwErr);
			return FALSE;
		}
	}
	//printf("运行驱动服务成功.\n");
	if (hServiceDDK)
	{
		CloseServiceHandle(hServiceDDK);
	}
	if (hServiceMgr)
	{
		CloseServiceHandle(hServiceMgr);
	}
	return TRUE;
}

// 卸载驱动
void UnLoadDriver(PCWSTR lpszDriverName)
{
	SC_HANDLE hServiceMgr = OpenSCManagerW(0, 0, SC_MANAGER_ALL_ACCESS);
	SC_HANDLE hServiceDDK = OpenServiceW(hServiceMgr, lpszDriverName, SERVICE_ALL_ACCESS);
	SERVICE_STATUS SvrStatus;
	ControlService(hServiceDDK, SERVICE_CONTROL_STOP, &SvrStatus);
	DeleteService(hServiceDDK);
	if (hServiceDDK)
	{
		CloseServiceHandle(hServiceDDK);
	}
	if (hServiceMgr)
	{
		CloseServiceHandle(hServiceMgr);
	}
}