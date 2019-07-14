#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <stdlib.h>
#include <iostream>
#include <Windows.h>
#include <psapi.h>
#include <tchar.h>
#include <stdio.h>
#include <lmcons.h>
#include <string>
#include <string.h>
#include <shellapi.h>

using namespace std;

#pragma comment (lib, "Ws2_32.lib")

void DoHax();

int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	Sleep(1000);
	if (GetKeyState(VK_CONTROL) & 0x8000) {
		DoHax();
	}
	else {
		ShellExecuteA(0, 0, "chrome.exe", "", "C:/Program Files(x86)/Google/Chrome/Application", 0);
	}
	return 0;
}

void DoHax() {
	DWORD aProcesses[1024], cbNeeded, cProcesses;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) return;

	cProcesses = cbNeeded / sizeof(DWORD);

	HANDLE process = (HANDLE)0;

	for (int i = 0; i < cProcesses; i++) {
		if (aProcesses[i]) {
			TCHAR pname[MAX_PATH] = TEXT("-");

			HANDLE tempprocess = OpenProcess(PROCESS_ALL_ACCESS, false, aProcesses[i]);
			if (tempprocess) {
				HMODULE hMod;
				DWORD cbNeeded2;

				if (EnumProcessModules(tempprocess, &hMod, sizeof(hMod), &cbNeeded)) {
					GetModuleBaseName(tempprocess, hMod, pname, sizeof(pname) / sizeof(TCHAR));
					if (!_tcscmp(pname, TEXT("PacketTracer6.exe"))) {
						process = tempprocess;
						break;
					}
				}
			}
		}
	}

	if (!process) return; // no packet tracer open

	int WPM_offset = ((int)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "WriteProcessMemory") - (int)GetModuleHandle(TEXT("kernel32.dll")));

	HMODULE hMods[1024];
	int PWriteProcessMemory = 0;

	EnumProcessModules(process, hMods, sizeof(hMods), &cbNeeded);
	for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
		TCHAR szModName[MAX_PATH];

		char name[MAX_PATH];
		if (GetModuleBaseNameA(process, hMods[i], name, MAX_PATH))
			if (!strcmp(name, "kernel32.dll"))
				PWriteProcessMemory = (int)hMods[i] + WPM_offset;
	}

	if (!PWriteProcessMemory) {
		cout << "Unable to locate a needed function\n";
		return;
	}

	void* mem = VirtualAllocEx(process, 0, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	cout << "allocation: " << hex << (int)mem << endl;

	int pprint = 0x00F1D980;
	char bytes[2000] = "\x60\x8B\x45\x08\x8D\xB8\xA0\x00\x00\x00\x80\xB8\xB4\x00\x00\x00\x0F\x0F\x8E\x02\x00\x00\x00\x8B\x3F\x68\xA7\x01\x45\x03\x57\xFF\x15\x44\x74\x6B\x02\x83\xC4\x08\x85\xC0\x0F\x85\x48\x00\x00\x00\x6A\x00\x6A\x02\x68\xC4\x01\x45\x03\x68\xB8\x9D\x42\x00\x6A\xFF\xE8\x6B\xD9\x7B\x72\x8B\x4D\x08\x68\xFC\x01\x45\x03\x8F\x05\xCE\x01\x45\x03\xC7\x05\xDE\x01\x45\x03\x17\x00\x00\x00\xC7\x05\xE2\x01\x45\x03\x1F\x00\x00\x00\x68\xCA\x01\x45\x03\xE8\x0F\xD9\xAC\xFD\xC6\x85\x97\xFE\xFF\xFF\x00\x68\xA2\x01\x45\x03\x57\xFF\x15\x44\x74\x6B\x02\x83\xC4\x08\x85\xC0\x0F\x85\x48\x00\x00\x00\x6A\x00\x6A\x02\x68\xC6\x01\x45\x03\x68\xB8\x9D\x42\x00\x6A\xFF\xE8\x0C\xD9\x7B\x72\x8B\x4D\x08\x68\x17\x02\x45\x03\x8F\x05\xCE\x01\x45\x03\xC7\x05\xDE\x01\x45\x03\x15\x00\x00\x00\xC7\x05\xE2\x01\x45\x03\x1F\x00\x00\x00\x68\xCA\x01\x45\x03\xE8\xB0\xD8\xAC\xFD\xC6\x85\x97\xFE\xFF\xFF\x00\x68\xAF\x01\x45\x03\x57\xFF\x15\x44\x74\x6B\x02\x83\xC4\x08\x85\xC0\x0F\x85\x48\x00\x00\x00\x6A\x00\x6A\x02\x68\xC4\x01\x45\x03\x68\x9D\xAA\xF5\x00\x6A\xFF\xE8\xAD\xD8\x7B\x72\x8B\x4D\x08\x68\x2F\x02\x45\x03\x8F\x05\xCE\x01\x45\x03\xC7\x05\xDE\x01\x45\x03\x0B\x00\x00\x00\xC7\x05\xE2\x01\x45\x03\x1F\x00\x00\x00\x68\xCA\x01\x45\x03\xE8\x51\xD8\xAC\xFD\xC6\x85\x97\xFE\xFF\xFF\x00\x68\xB8\x01\x45\x03\x57\xFF\x15\x44\x74\x6B\x02\x83\xC4\x08\x85\xC0\x0F\x85\x48\x00\x00\x00\x6A\x00\x6A\x02\x68\xC8\x01\x45\x03\x68\x9D\xAA\xF5\x00\x6A\xFF\xE8\x4E\xD8\x7B\x72\x8B\x4D\x08\x68\x3C\x02\x45\x03\x8F\x05\xCE\x01\x45\x03\xC7\x05\xDE\x01\x45\x03\x0C\x00\x00\x00\xC7\x05\xE2\x01\x45\x03\x1F\x00\x00\x00\x68\xCA\x01\x45\x03\xE8\xF2\xD7\xAC\xFD\xC6\x85\x97\xFE\xFF\xFF\x00\x61\x0F\xB6\x85\x97\xFE\xFF\xFF\xE9\xC4\x74\xAB\xFD\x6C\x6F\x63\x6B\x00\x6E\x6F\x20\x6C\x6F\x63\x6B\x00\x63\x6F\x6D\x70\x6C\x65\x74\x65\x00\x6E\x6F\x20\x63\x6F\x6D\x70\x6C\x65\x74\x65\x00\x90\x90\x75\x36\x74\x0C\x00\x00\x00\x00\x17\x02\x45\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x00\x1F\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x41\x6C\x6C\x20\x69\x6E\x74\x65\x72\x66\x61\x63\x65\x73\x20\x75\x6E\x6C\x6F\x63\x6B\x65\x64\x20\x20\x20\x00\x49\x6E\x74\x65\x72\x66\x61\x63\x65\x20\x6C\x6F\x63\x6B\x73\x20\x72\x65\x73\x65\x74\x20\x20\x00\x43\x6F\x6D\x70\x6C\x65\x74\x65\x20\x6F\x6E\x20\x00\x43\x6F\x6D\x70\x6C\x65\x74\x65\x20\x6F\x66\x66\x00";
	
	// direct reference
	*(int*)(bytes + 0x1A) = (int)mem + 0x1A7;
	*(int*)(bytes + 0x35) = (int)mem + 0x1C4;
	*(int*)(bytes + 0x49) = (int)mem + 0x1FC;
	*(int*)(bytes + 0x4F) = (int)mem + 0x1CE;
	*(int*)(bytes + 0x55) = (int)mem + 0x1DE;
	*(int*)(bytes + 0x5F) = (int)mem + 0x1E2;
	*(int*)(bytes + 0x68) = (int)mem + 0x1CA;
	*(int*)(bytes + 0x79) = (int)mem + 0x1A2;
	*(int*)(bytes + 0x94) = (int)mem + 0x1C6;
	*(int*)(bytes + 0xA8) = (int)mem + 0x217;
	*(int*)(bytes + 0xAE) = (int)mem + 0x1CE;
	*(int*)(bytes + 0xB4) = (int)mem + 0x1DE;
	*(int*)(bytes + 0xBE) = (int)mem + 0x1E2;
	*(int*)(bytes + 0xC7) = (int)mem + 0x1CA;
	*(int*)(bytes + 0xD8) = (int)mem + 0x1AF;
	*(int*)(bytes + 0xF3) = (int)mem + 0x1C4;
	*(int*)(bytes + 0x107)= (int)mem + 0x22F;
	*(int*)(bytes + 0x10D)= (int)mem + 0x1CE;
	*(int*)(bytes + 0x113)= (int)mem + 0x1DE;
	*(int*)(bytes + 0x11D)= (int)mem + 0x1E2;
	*(int*)(bytes + 0x126)= (int)mem + 0x1CA;
	*(int*)(bytes + 0x137)= (int)mem + 0x1B8;
	*(int*)(bytes + 0x152)= (int)mem + 0x1C8;
	*(int*)(bytes + 0x166)= (int)mem + 0x23C;
	*(int*)(bytes + 0x16C)= (int)mem + 0x1CE;
	*(int*)(bytes + 0x172)= (int)mem + 0x1DE;
	*(int*)(bytes + 0x17C)= (int)mem + 0x1E2;
	*(int*)(bytes + 0x185)= (int)mem + 0x1CA;
  
	// jump/call offset
	*(int*)(bytes + 0x41) = PWriteProcessMemory - ((int)mem + 0x45);
	*(int*)(bytes + 0x6D) = pprint - ((int)mem + 0x71);
	*(int*)(bytes + 0xA0) = PWriteProcessMemory - ((int)mem + 0xA4);
	*(int*)(bytes + 0xCC) = pprint - ((int)mem + 0xD0);
	*(int*)(bytes + 0xFF) = PWriteProcessMemory - ((int)mem + 0x103);
	*(int*)(bytes + 0x12B) = pprint - ((int)mem + 0x12F);
	*(int*)(bytes + 0x15E) = PWriteProcessMemory - ((int)mem + 0x162);
	*(int*)(bytes + 0x18A) = pprint - ((int)mem + 0x18E);
	*(int*)(bytes + 0x19E) = 0x00F07666 - ((int)mem + 0x1A2);

	char jmppayload[] = "\xE9\x00\x00\x00\x00\x90\x90";
	*(int*)(jmppayload + 1) = ((int)mem - 0x00F07664);


	WriteProcessMemory(process, mem, bytes, 2000, 0);
	WriteProcessMemory(process, (void*)0x00F0765F, jmppayload, 7, 0);

}

