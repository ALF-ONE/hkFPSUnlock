#include <Windows.h>
#include <string>

#include "urmem/urmem.hpp"

class FPSUnlock
{
public:
	static auto Init() -> void
	{
		Thread = std::make_shared<CThread>(nullptr, NULL, [](LPVOID) -> DWORD
		{
			for (urmem::address_t baseAddress = NULL; baseAddress == NULL; std::this_thread::sleep_for(std::chrono::milliseconds(100)))
			{
				baseAddress = reinterpret_cast<urmem::address_t>(GetModuleHandle("samp.dll"));
				if (baseAddress != NULL)
				{
					urmem::sig_scanner scan;
					if (!scan.init(baseAddress)) break;

					urmem::address_t AddClientMessageAddress, FPSUnlockAddress, FPSLimitAddress;
					if (!scan.find("\x56\x8B\x74\x24\x0C\x8B\xC6\x57\x8B\xF9", "xxxxxxxxxx", AddClientMessageAddress)) break;
					if (!scan.find("\xE8\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x85\xC0\x74\x00\x8B\x80\x00\x00\x00\x00\x8B\x40", "x????x????xxx?xx????xx", FPSUnlockAddress)) break;
					if (!scan.find("\x83\xFE\x14\x72\x00\x83\xFE\x5A", "xxxx?xxx", FPSLimitAddress)) break;

					hkADDClientMessage = std::make_shared<urmem::hook>(AddClientMessageAddress, urmem::get_func_addr(&HOOK_ADDClientMessage), urmem::hook::type::jmp, 5);
					hkFPSUnlock = std::make_shared<urmem::hook>(FPSUnlockAddress, urmem::get_func_addr(&HOOK_FPSUnlock), urmem::hook::type::call, 5);
					FPSLimitPatch[0] = std::make_shared<urmem::patch>(FPSLimitAddress, urmem::bytearray_t{ 0x56 });
					FPSLimitPatch[1] = std::make_shared<urmem::patch>(FPSLimitAddress + 0x2D, urmem::bytearray_t(20, 0x90));
					hkFPSLimit = std::make_shared<urmem::hook>(FPSLimitAddress + 0x01, urmem::get_func_addr(&HOOK_FPSLimit), urmem::hook::type::call, 9);

					gamePatch[0] = std::make_shared<urmem::patch>(0xBAB318, urmem::bytearray_t{ 0x00 });
					gamePatch[1] = std::make_shared<urmem::patch>(0x53E94C, urmem::bytearray_t{ 0x00 });
				}
			}

			ExitThread(0);
			return 0;
		}, nullptr, NULL, nullptr);
	}

private:
	class CThread
	{
	public:
		explicit CThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) :
			hHandle{ CreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId) } {}
		~CThread() {
			if (hHandle) CloseHandle(hHandle);
		}
	private:
		HANDLE hHandle;
	};

	static auto __stdcall HOOK_ADDClientMessage(DWORD dwColor, const char* szText) -> void {
		__asm mov _thisChat, ecx
		hkADDClientMessage->disable();
		return ADDClientMessage(dwColor, szText);
	}

	static auto __stdcall HOOK_FPSUnlock() -> void {
		if (*reinterpret_cast<urmem::byte_t*>(0xBA6794) == 1) urmem::call_function<urmem::calling_convention::thiscall, int>(hkFPSUnlock->get_original_addr());
	}

	static auto __stdcall HOOK_FPSLimit(int iValue) -> void {
		*reinterpret_cast<urmem::byte_t*>(0xBA6794) ^= 1;
		urmem::call_function<urmem::calling_convention::thiscall, int, void*>(0x57C660, reinterpret_cast<void*>(0xBA6748)); // CMenuManager::Save
		ADDClientMessage(0x88AA62FF, std::string(*reinterpret_cast<urmem::byte_t*>(0xBA6794) ? "-> Frame Limiter: " + std::to_string(iValue) : "-> Frame Limiter: disabled").c_str());
	}

	static auto ADDClientMessage(DWORD dwColor, const char* szText) -> void {
		if (_thisChat) urmem::call_function<urmem::calling_convention::thiscall, int, void*, DWORD, const char*>(hkADDClientMessage->get_original_addr(), _thisChat, dwColor, szText);
	}

	static void* _thisChat;
	static std::shared_ptr<CThread> Thread;
	static std::shared_ptr<urmem::patch> FPSLimitPatch[2], gamePatch[2];
	static std::shared_ptr<urmem::hook> hkADDClientMessage, hkFPSUnlock, hkFPSLimit;
};

void* FPSUnlock::_thisChat;
std::shared_ptr<FPSUnlock::CThread> FPSUnlock::Thread;
std::shared_ptr<urmem::patch> FPSUnlock::FPSLimitPatch[2], FPSUnlock::gamePatch[2];
std::shared_ptr<urmem::hook> FPSUnlock::hkADDClientMessage, FPSUnlock::hkFPSUnlock, FPSUnlock::hkFPSLimit;

auto APIENTRY DllMain(HMODULE hModule, DWORD dwReasonForCall, LPVOID lpReserved) -> BOOL
{
	switch (dwReasonForCall)
	{
	case DLL_PROCESS_ATTACH:
		FPSUnlock::Init();
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}