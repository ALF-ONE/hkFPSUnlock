#include <Windows.h>
#include <string>

#include "urmem/urmem.hpp"

class CFPSUnlock
{
public:
	static auto Init() -> void {
		hkGameLoop = std::make_shared<urmem::hook>(0x53BEE0, urmem::get_func_addr(&HOOK_GameLoop), urmem::hook::type::jmp);
	}

private:
	static auto __stdcall HOOK_GameLoop() -> void {
		hkGameLoop->call<urmem::calling_convention::stdcall, void>();

		urmem::address_t baseAddress = reinterpret_cast<urmem::address_t>(GetModuleHandle("samp.dll"));
		if (baseAddress == NULL)
			return;

		urmem::sig_scanner scan;
		if (!scan.init(baseAddress))
			return;

		urmem::address_t AddClientMessageAddress;
		if (!scan.find("\x56\x8B\x74\x24\x0C\x8B\xC6\x57\x8B\xF9", "xxxxxxxxxx", AddClientMessageAddress))
			return;

		urmem::address_t FPSUnlockAddress;
		if (!scan.find("\xE8\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x85\xC0\x74\x00\x8B\x80\x00\x00\x00\x00\x8B\x40", "x????x????xxx?xx????xx", FPSUnlockAddress))
			return;

		urmem::address_t FPSLimitAddress;
		if (!scan.find("\x83\xFE\x14\x72\x00\x83\xFE\x5A", "xxxx?xxx", FPSLimitAddress))
			return;

		urmem::address_t SleepHookAddress;
		if (!scan.find("\x6A\x01\xFF\x15\x00\x00\x00\x00\xBA\x80\x1A\x56\x00", "xxxx????xxxxx", SleepHookAddress))
			return;

		hkADDClientMessage = std::make_shared<urmem::hook>(AddClientMessageAddress, urmem::get_func_addr(&HOOK_ADDClientMessage), urmem::hook::type::jmp, 5);
		hkFPSUnlock = std::make_shared<urmem::hook>(FPSUnlockAddress, urmem::get_func_addr(&HOOK_FPSUnlock), urmem::hook::type::call, 5);
		FPSLimitPatch[0] = std::make_shared<urmem::patch>(FPSLimitAddress, urmem::bytearray_t{ 0x56 });
		FPSLimitPatch[1] = std::make_shared<urmem::patch>(FPSLimitAddress + 0x2D, urmem::bytearray_t(20, 0x90));
		hkFPSLimit = std::make_shared<urmem::hook>(FPSLimitAddress + 0x01, urmem::get_func_addr(&HOOK_FPSLimit), urmem::hook::type::call, 9);
		FPSLimitPatch[2] = std::make_shared<urmem::patch>(SleepHookAddress, urmem::bytearray_t(8, 0x90));

		gamePatch[0] = std::make_shared<urmem::patch>(0xBAB318, urmem::bytearray_t{ 0x00 });
		gamePatch[1] = std::make_shared<urmem::patch>(0x53E94C, urmem::bytearray_t{ 0x00 });

		hkGameLoop->disable();
	}

	static auto __stdcall HOOK_ADDClientMessage(DWORD dwColor, const char* szText) -> void {
		__asm mov _thisChat, ecx

		hkADDClientMessage->disable();
		return ADDClientMessage(dwColor, szText);
	}

	static auto __fastcall HOOK_FPSUnlock(void *_this) -> void {
		if (*reinterpret_cast<urmem::byte_t*>(0xBA6794) == 1)
			hkFPSUnlock->call<urmem::calling_convention::thiscall, int, void*>(_this);
	}

	static auto __stdcall HOOK_FPSLimit(int iValue) -> void {
		*reinterpret_cast<urmem::byte_t*>(0xBA6794) ^= 1;

		urmem::call_function<urmem::calling_convention::thiscall, int, void*>(0x57C660, reinterpret_cast<void*>(0xBA6748)); // CMenuManager::Save
		ADDClientMessage(0x88AA62FF, std::string(*reinterpret_cast<urmem::byte_t*>(0xBA6794) ? "-> Frame Limiter: " + std::to_string(iValue) : "-> Frame Limiter: disabled").c_str());
	}

	static auto ADDClientMessage(DWORD dwColor, const char* szText) -> void {
		if (_thisChat)
			hkADDClientMessage->call<urmem::calling_convention::thiscall, int, void*, DWORD, const char*>(_thisChat, dwColor, szText);
	}

	static void* _thisChat;
	static std::shared_ptr<urmem::patch> FPSLimitPatch[3], gamePatch[2];
	static std::shared_ptr<urmem::hook> hkGameLoop, hkADDClientMessage, hkFPSUnlock, hkFPSLimit;
};

void* CFPSUnlock::_thisChat;
std::shared_ptr<urmem::patch> CFPSUnlock::FPSLimitPatch[3], CFPSUnlock::gamePatch[2];
std::shared_ptr<urmem::hook> CFPSUnlock::hkGameLoop, CFPSUnlock::hkADDClientMessage, CFPSUnlock::hkFPSUnlock, CFPSUnlock::hkFPSLimit;

auto APIENTRY DllMain(HMODULE hModule, DWORD dwReasonForCall, LPVOID lpReserved) -> BOOL {
	switch (dwReasonForCall) {
	case DLL_PROCESS_ATTACH:
		CFPSUnlock::Init();
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}