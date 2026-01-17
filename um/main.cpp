/*
	Uses the "hv" hypervisor project to install EPT hooks on pages in other processes. Thank you for https://github.com/jonomango/hv !
	This example demonstrates EPT hooking (cross-process redirected execution) and tracepoints
	By AlSch092 @ Github
*/
#include "hv.h"
#include "dumper.h"
#include "helpers.hpp"

#define get_guest_pfn(target_gpa) (target_gpa >> 12)

struct ept_hook
{
	DWORD target_processId = 0; //must be filled before passing to hook_ept
	uintptr_t target_address = 0; //virtual address of target page -> must be filled before passing to hook_ept
	uintptr_t target_phys_frame = 0; // original physical frame number -> filled by hook_ept
	uintptr_t hook_address = 0; //virtual address of replacement page -> filled by hook_ept
	uintptr_t hooked_phys_frame = 0; // -> filled by hook_ept
	bool is_hooked = false;
};

#pragma section(".mycode", execute, read)
__declspec(code_seg(".mycode"))
/*
	This func will be executed in a different process via EPT hooking
*/
void TestFunc()
{
	byte msg_bytes[] = { 0x48,0x65,0x6C,0x6C,0x6F,0x20,0x66,0x72,0x6F,0x6D,0x20,0x68,0x6F,0x6F,0x6B,0x65,0x64,0x20,0x66,0x75,0x6E,0x63,0x74,0x69,0x6F,0x6E,0x21,0x0A, 0x00 };

	// puts example -> easy to see in console output
	byte module_name[] = { 'u', 0x00, 'c', 0x00, 'r',0x00, 't', 0x00, 'b', 0x00, 'a', 0x00,'s', 0x00,'e', 0x00, '.',0x00, 'd', 0x00,'l', 0x00, 'l', 0x00, 0x00 };
	byte func_name[] = { 'p', 'u', 't', 's', 0x00 };

	uintptr_t addr = (uintptr_t)_GetProcAddress((const wchar_t*)module_name, (const LPCSTR)func_name); //non WINAPI GetProcAddress

	if (addr) //API-less puts call
	{
		typedef int (CDECL* puts_t)(const char*);
		puts_t _puts = (puts_t)addr;
		_puts((const char*)msg_bytes);
	}

	// MessageBoxA example -> inserting a message box in execution flow of another process
	//byte module_name[] = {'U', 0x00, 'S', 0x00, 'E',0x00, 'R',0x00, '3', 0x00, '2', 0x00, '.',0x00, 'd', 0x00,'l', 0x00, 'l', 0x00, 0x00};
	//byte func_name[] = { 'M', 'e', 's', 's','a','g','e','B','o','x', 'A', 0x00};

	//uintptr_t addr = (uintptr_t)_GetProcAddress((const wchar_t*)module_name, (const LPCSTR)func_name);

	//if (addr) //API-less MessageBoxA call
	//{
	//	typedef int (WINAPI* MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
	//	MessageBoxA_t _MessageBoxA = (MessageBoxA_t)addr;
	//	_MessageBoxA(0, (LPCSTR)msg_bytes, 0, MB_OK);
	//}
}

#pragma code_seg(pop)

#pragma code_seg(".text")

/*
	Hooks an EPT entry to redirect execution from target_address in target_processId to hook_address in the current process
	Fills the member hook_info.hook_address with an allocated page if it was NULL beforehand, you should then memcpy your hook code into that page
	after this func returns
	...Fills members hooked_phys_frame, target_phys_frame, and hook_address
*/
bool hook_ept(ept_hook& hook_info)
{
	hook_info.hooked_phys_frame = 0;

	if (!hv::is_hv_running())
	{
		printf("HV not running.\n");
		return false;
	}

	uintptr_t cr3 = hv::query_process_cr3(hook_info.target_processId);

	printf("Target CR3: 0x%I64X\n", cr3);

	uintptr_t gpa = hv::get_physical_address(cr3, (const void*)hook_info.target_address);

	if (!gpa)
	{
		printf("[ERROR] Failed to get physical address of target/original page!\n");
		return false;
	}

	uintptr_t gfn = get_guest_pfn(gpa);

	if (hook_info.hook_address == NULL) //if there is no "source", allocate a new page for our hook's execution to be
	{
		HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, hook_info.target_processId); //todo: incorporate EasyHandles driver to guarantee handle acquisition

		if (!hProc)
		{
			printf("[ERROR] Failed to open target process - error: %d\n", GetLastError());
			return false;
		}

		BYTE cpy_buffer[0x1000] = { 0 };

		SIZE_T dwBytesRead = 0;

		if (!ReadProcessMemory(hProc, (LPCVOID)hook_info.target_address, cpy_buffer, 0x1000, &dwBytesRead))
		{
			printf("[ERROR] Failed to fetch target page bytes - error: %d\n", GetLastError());
			return false;
		}

		CloseHandle(hProc);

		LPVOID pHookPage = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		if (!pHookPage)
		{
			printf("[ERROR] Failed to allocate hook page: %d\n", GetLastError());
			return false;
		}

		hook_info.hook_address = (uintptr_t)pHookPage;

		//copy entire page so that any other funcs called on that page from the target process won't cause crashes
		memcpy((void*)pHookPage, cpy_buffer, 0x1000);
	}

	cr3 = hv::query_process_cr3(GetCurrentProcessId());

	printf("Current cr3: %llX, hook address: %llX\n", cr3, hook_info.hook_address);

	uintptr_t new_gpa = hv::get_physical_address(cr3, (const void*)hook_info.hook_address);

	if (!new_gpa)
	{
		printf("[ERROR] Failed to get physical address of hook page!\n");
		return false;
	}

	uintptr_t new_gfn = get_guest_pfn(new_gpa);

	printf("Hook page physical addr: %llX, frame %llX\n", new_gpa, new_gfn);

	hv::for_each_cpu([&](uint32_t)
		{
			if (!hv::install_ept_hook(gfn, new_gfn))
				printf("Failed to install EPT hook!\n");
		});

	hook_info.target_phys_frame = gfn;
	hook_info.hooked_phys_frame = new_gfn;
	hook_info.is_hooked = true;
	return true;
}

void unhook_ept(ept_hook& hook_info)
{
	hv::for_each_cpu([&](uint32_t)
		{
			hv::remove_ept_hook(hook_info.target_phys_frame);
		});

	if (hook_info.hook_address)
		if (!VirtualFree((LPVOID)hook_info.hook_address, 0, MEM_RELEASE))
			printf("[WARNING - unhook_ept] Failed to free hook page memory: %d\n", GetLastError());

	hook_info.is_hooked = false;
}


ept_hook example_hook_ept(__in const DWORD target_pid, __in const uintptr_t src_addr)
{
	if (target_pid == 0 || src_addr == NULL)
	{
		printf("One or more parameters were NULL @ example_hook_ept\n");
		return {};
	}

	ept_hook hook_info = { 0 };
	hook_info.target_processId = target_pid;
	hook_info.target_address = src_addr;

	uintptr_t target_cr3 = hv::query_process_cr3(target_pid);

	if (!target_cr3)
	{
		printf("[WARNING] Failed to get target process CR3!\n");
		return {};
	}

	if (!hook_ept(hook_info))
	{
		printf("[WARNING] Failed to hook EPT of process %d at address %llX!\n", target_pid, src_addr);
		return {};
	}

	if (!hook_info.hook_address)
	{
		printf("[WARNING] hook_info.hook_address was 0!\n");
		return {};
	}

	//after our new page memory is allocated, we memcpy our hook bytes into it before it's called
	memcpy((void*)(hook_info.hook_address), (const void*)TestFunc, 0x1FA);
	printf("hook_info.hook_address: %llX\n", hook_info.hook_address);

	return hook_info;
}

bool add_monitored_mem_range(__in const DWORD pid, __in const uintptr_t guest_virtual_addr, __in const int size, __in const uint8_t access_type)
{
	if (pid == 0 || guest_virtual_addr == NULL || size <= 0)
	{
		printf("One or more parameters were NULL/invalid @ add_monitored_mem_range\n");
		return false;
	}

	uintptr_t target_cr3 = hv::query_process_cr3(pid);

	if (!target_cr3)
	{
		printf("[WARNING] Failed to get target process CR3!\n");
		system("pause");
		return false;
	}

	uintptr_t gpa = hv::get_physical_address(target_cr3, (const void*)guest_virtual_addr);

	if (!gpa)
	{
		printf("[ERROR] Failed to get physical address of target/original page!\n");
		return false;
	}

	hv::for_each_cpu([gpa, size, access_type](uint32_t) {
		hv::install_mmr(gpa, size, access_type); //mmr_memory_mode_x
		});

	printf("Added monitored memory range at GPA: %llX, size: %d, access type: %d\n", gpa, size, access_type);
}

int main(int argc, char** argv)
{
	if (!hv::is_hv_running())
	{
		printf("HV not running.\n");
		return 0;
	}

	DWORD target_pid = 17380; //process ID of TestEPTTarget.exe (other project in solution)
	uintptr_t src_addr = 0x7FF693BEA000; //virtual address in target_pid to hook -> in this case, it's the address of `MessageBoxTest` in TestEPTTarget.exe (other project in solution)

	if (argc > 1)
	{
		target_pid = atoi(argv[1]);
		src_addr = strtoull(argv[2], nullptr, 16);
	}

	bool monitoring_enabled = true; //mmr example to log execution access -> very naice for tracing/debugging live execution in a process
	bool ept_hooking_enabled = false;
	ept_hook hook_info;

	if (!add_monitored_mem_range(target_pid, src_addr, 0x1000, 4))
	{
		printf("Failed to add to mmr, check params for NULL values.\n");
		return -1;
	}

	if (ept_hooking_enabled)
	{
		hook_info = example_hook_ept(target_pid, src_addr); // ept hook example -> changes 
	}

	FILE* file = nullptr;
	fopen_s(&file, "hvlog.txt", "a");

	if (file == NULL)
	{
		printf("[WARNING] File was NULL!\n");
		return false;
	}

	while (!GetAsyncKeyState(VK_F1))
	{
		// flush the logs
		uint32_t count = 512;
		hv::logger_msg msgs[512];
		hv::flush_logs(count, msgs);

		// print the logs
		for (uint32_t i = 0; i < count; ++i)
		{
			printf("[%I64u][CPU=%u] %s\n", msgs[i].id, msgs[i].aux, msgs[i].data);
			fprintf(file, "[%I64u][CPU=%u] %s\n", msgs[i].id, msgs[i].aux, msgs[i].data);
		}

		fflush(file);
		Sleep(1);
	}

	fclose(file);

	if (monitoring_enabled)
	{
		hv::for_each_cpu([](uint32_t)
			{
				hv::remove_all_mmrs();
			});
	}

	if (ept_hooking_enabled && hook_info.is_hooked)
	{
		unhook_ept(hook_info);
		printf("Unhooked EPT...\n");
	}

	system("pause");
	return 0;
}

#pragma code_seg(pop)