// ept_hook_target.cpp : Target application for EPT hooking tests. um.exe will hook functions in this process via EPT manipulation.
// Uses the Intel hv from project https://github.com/jonomango/hv

#include <iostream>
#include <Windows.h>
#include <psapi.h>
#include <vector>

#pragma section(".mycode3", execute, read) //force each function into its own page for the sake of these tests
__declspec(code_seg(".mycode3"))
// EPT hook test -> changing return value of Test() from 42 to something else (without modifying any bytes in the target or opening a handle)
int Test()
{
	return 42;
}

#pragma code_seg(pop)

#pragma section(".mycode4", execute, read) //force each function into its own page for the sake of these tests
__declspec(code_seg(".mycode4"))
// EPT hook test -> Change a call from MessageBoxA() to ucrtbase.puts(), page from process B executed in process A context (all APIs must be looked up dynamically)
void MessageBoxTest()
{
	MessageBoxA(0, "Hello from hooked function!", "Hooked", MB_OK);
}

#pragma code_seg(pop)

#pragma section(".mycode2", execute, read)
__declspec(code_seg(".mycode2"))
// Random function to enumerate loaded drivers to show regular process activity during EPT hooking
std::vector<wchar_t*> GetDrivers()
{
	DWORD cbNeeded;
	HMODULE drivers[1024];
	DWORD numDrivers;

	std::vector<wchar_t*> driverList;

	if (!EnumDeviceDrivers((LPVOID*)drivers, sizeof(drivers), &cbNeeded))
	{
		printf("EnumDeviceDrivers failed; error = %lu\n", GetLastError());
		return {};
	}

	numDrivers = cbNeeded / sizeof(HMODULE);

	for (DWORD i = 0; i < numDrivers; i++)
	{
		TCHAR driverName[MAX_PATH];
		TCHAR driverPath[MAX_PATH];

		if (GetDeviceDriverBaseName(drivers[i], driverName, MAX_PATH) && GetDeviceDriverFileName(drivers[i], driverPath, MAX_PATH))
		{
			wchar_t* driverPathCopy = new wchar_t[wcslen(driverPath) + 1];
			wcscpy_s(driverPathCopy, wcslen(driverPath) + 1, driverPath);
			driverList.push_back(driverPathCopy);
		}
	}

	return driverList;
}

#pragma code_seg(pop)

int main()
{
	system("pause"); //let the program hang so that we can run um.exe which hooks EPT or other work against our current process

	for (int i = 0; i < 10; i++)
	{
		int result = Test();
		MessageBoxTest(); //this will become a puts() instead after EPT hooking from um.exe
		printf("Result: %d\n", result);
	}

	auto drivers = GetDrivers();

	for (auto& driver : drivers)
	{
		std::wcout << L"Driver: " << driver << L"\n";
		delete[] driver; // Clean up allocated memory
	}

	return 0;
}
