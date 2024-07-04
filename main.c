#include <windows.h>
#include <stdio.h>

// missing in mingw-w64 for some reason
#ifndef SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME
#define SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME TEXT("SeDelegateSessionUserImpersonatePrivilege")
#endif

#define MAX_PRIVILEGES 36
const WCHAR* ALL_TOKEN_PRIVILEGES[MAX_PRIVILEGES] = {
	SE_ASSIGNPRIMARYTOKEN_NAME,
	SE_AUDIT_NAME,
	SE_BACKUP_NAME,
	SE_CHANGE_NOTIFY_NAME,
	SE_CREATE_GLOBAL_NAME,
	SE_CREATE_PAGEFILE_NAME,
	SE_CREATE_PERMANENT_NAME,
	SE_CREATE_SYMBOLIC_LINK_NAME,
	SE_CREATE_TOKEN_NAME,
	SE_DEBUG_NAME,
	SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME,
	SE_ENABLE_DELEGATION_NAME,
	SE_IMPERSONATE_NAME,
	SE_INCREASE_QUOTA_NAME,
	SE_INC_BASE_PRIORITY_NAME,
	SE_INC_WORKING_SET_NAME,
	SE_LOAD_DRIVER_NAME,
	SE_LOCK_MEMORY_NAME,
	SE_MACHINE_ACCOUNT_NAME,
	SE_MANAGE_VOLUME_NAME,
	SE_PROF_SINGLE_PROCESS_NAME,
	SE_RELABEL_NAME,
	SE_REMOTE_SHUTDOWN_NAME,
	SE_RESTORE_NAME,
	SE_SECURITY_NAME,
	SE_SHUTDOWN_NAME,
	SE_SYNC_AGENT_NAME,
	SE_SYSTEMTIME_NAME,
	SE_SYSTEM_ENVIRONMENT_NAME,
	SE_SYSTEM_PROFILE_NAME,
	SE_TAKE_OWNERSHIP_NAME,
	SE_TCB_NAME,
	SE_TIME_ZONE_NAME,
	SE_TRUSTED_CREDMAN_ACCESS_NAME,
	SE_UNDOCK_NAME,
	SE_UNSOLICITED_INPUT_NAME
};

// macro pseudo-function to abort with a formatted message
#define wabort(format, ...) do { \
	fwprintf(stderr, TEXT(format "\n"), ##__VA_ARGS__); \
	exit(1); \
} while(0)

void set_token_privilege(HANDLE token, const WCHAR* name) {
	LUID luid = { 0 };
	if(LookupPrivilegeValue(NULL, name, &luid) == 0 && GetLastError() != ERROR_NO_SUCH_PRIVILEGE) {
		wabort("Failed to lookup privilege value for %ls", name);
	}
	TOKEN_PRIVILEGES privs = {
		.PrivilegeCount = 1,
		.Privileges[0] = {
			.Luid = luid,
			.Attributes = SE_PRIVILEGE_ENABLED
		}
	};
	if(AdjustTokenPrivileges(token, FALSE, &privs, 0, NULL, NULL) == 0) {
		wabort("Failed to adjust token privileges for %ls", name);
	}
}

void set_debug_privilege() {
	HANDLE token = NULL;
	ImpersonateSelf(SecurityImpersonation);
	if(OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &token) == 0) {
		wabort("Failed to open thread access token");
	}
	set_token_privilege(token, SE_DEBUG_NAME);
}

void set_all_privileges(PROCESS_INFORMATION proc) {
	HANDLE token = NULL;
	if(OpenProcessToken(proc.hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token) == 0) {
		wabort("Failed to open process access token");
	}
	for(int i = 0; i < MAX_PRIVILEGES; i++) {
		set_token_privilege(token, ALL_TOKEN_PRIVILEGES[i]);
	}
}

DWORD get_trusted_process_id() {
	HANDLE manager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if(manager == NULL) {
		wabort("Failed to open service control manager");
	}
	HANDLE ti = OpenService(manager, TEXT("TrustedInstaller"), SERVICE_START | SERVICE_QUERY_STATUS);
	if(ti == NULL) {
		wabort("Failed to open TrustedInstaller service (are you running as an Administrator?)");
	}
	if(StartService(ti, 0, NULL) == 0 && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
		wabort("Failed to start TrustedInstaller service");
	}
	SERVICE_STATUS_PROCESS status = { 0 };
	DWORD bytes = 0;
	QueryServiceStatusEx(ti, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(status), &bytes);
	if(status.dwCurrentState != SERVICE_RUNNING && status.dwCurrentState != SERVICE_START_PENDING) {
		wabort("Failed to run TrustedInstaller service");
	}
	DWORD pid = status.dwProcessId;
	CloseServiceHandle(ti);
	CloseServiceHandle(manager);
	return pid;
}

STARTUPINFOEX startup_info_init(HANDLE tip) {
	STARTUPINFOEX startup = {
		.StartupInfo = {
			.cb = sizeof(STARTUPINFOEX),
			.dwFlags = STARTF_USESHOWWINDOW,
			.wShowWindow = SW_SHOWNORMAL
		}
	};
	SIZE_T sz = 0;
	InitializeProcThreadAttributeList(NULL, 1, 0, &sz);
	startup.lpAttributeList = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
	InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &sz);
	UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &tip, sizeof(HANDLE), NULL, NULL);
	return startup;
}

void startup_info_free(STARTUPINFOEX startup) {
	DeleteProcThreadAttributeList(startup.lpAttributeList);
	if(HeapFree(GetProcessHeap(), 0, startup.lpAttributeList) == 0) {
		wabort("Failed to free attribute list");
	}
}

PROCESS_INFORMATION create_process_with_startup(STARTUPINFOEX startup, WCHAR* command) {
	PROCESS_INFORMATION proc = { 0 };
	DWORD flags = CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE;
	if(CreateProcess(NULL, command, NULL, NULL, FALSE, flags, NULL, NULL, (LPSTARTUPINFOW)&startup, &proc) == 0) {
		wabort("Failed to create process %ls", command);
	}
	return proc;
}

PROCESS_INFORMATION create_process_with_ti_parent(WCHAR* command) {
	HANDLE tip = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, get_trusted_process_id());
	if(tip == NULL) {
		wabort("Failed to open TrustedInstaller process");
	}
	STARTUPINFOEX startup = startup_info_init(tip);
	PROCESS_INFORMATION proc = create_process_with_startup(startup, command);
	startup_info_free(startup);
	return proc;
}

void run_as_ti(WCHAR* command) {
	PROCESS_INFORMATION proc = create_process_with_ti_parent(command);
	set_all_privileges(proc);
	ResumeThread(proc.hThread);
	CloseHandle(proc.hThread);
	CloseHandle(proc.hProcess);
}

// cmdline cannot be a pointer to read-only memory so allocate rw buffer
WCHAR* cmd_init(WCHAR* cmdline) {
	SIZE_T sz = (wcslen(cmdline) + 1) * sizeof(WCHAR);
	WCHAR* buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
	if(buffer == NULL) {
		wabort("Failed to allocate command-line buffer");
	}
	memcpy(buffer, cmdline, sz);
	return buffer;
}

void cmd_free(WCHAR* command) {
	if(HeapFree(GetProcessHeap(), 0, command) == 0) {
		wabort("Failed to free command buffer");
	}
}

WCHAR* get_command_line(int argc, WCHAR* argv[]) {
	WCHAR* cmdline = TEXT("powershell.exe");
	// user-provided command-line arguments to execute
	if(argc > 1) {
		WCHAR* substr = wcsstr(GetCommandLine(), argv[0]);
		if (substr != NULL) {
			cmdline = substr + wcslen(argv[0]) + 1;
		}
	}
	wprintf(TEXT("run: %ls\n"), cmdline);
	return cmdline;
}

int wmain(int argc, WCHAR* argv[]) {
	WCHAR* cmdline = get_command_line(argc, argv);
	set_debug_privilege();
	WCHAR *command = cmd_init(cmdline);
	run_as_ti(command);
	cmd_free(command);
	return 0;
}
