#include <Windows.h>
#include <AclAPI.h>
#include <sddl.h>
#include <string>
#include <stdexcept>
#include <type_traits>
#include <filesystem>
#include <LM.h>
#include <fstream>
#include <utility>
#include <vector>
#include <iostream>
#pragma comment(lib, "Netapi32.lib")

template<typename EF>
class InferiorScopeExit {
public:
	template<typename EFP>
	InferiorScopeExit(EFP&& f) : exit_function(std::forward<EFP>(f)) {}
	InferiorScopeExit(InferiorScopeExit&& o) noexcept(std::is_nothrow_move_constructible_v<EF>) : exit_function(std::move(o.exit_function))
	{
		o.release();
	}
	~InferiorScopeExit()
	{
		if (execute_on_destruction) exit_function();
	}
	void release() noexcept { execute_on_destruction = false; }
private:
	EF exit_function;
	bool execute_on_destruction{ true };
};

template <class EF>InferiorScopeExit<std::decay_t<EF>> MakeInferiorScopeExit(EF&& exit_function) { return { std::forward<EF>(exit_function) }; }

template<typename T, std::enable_if_t<std::is_same_v<T, DWORD>, std::nullptr_t> = nullptr>
inline std::string GetErrorMessage(const T& ErrorCode) {
	char* lpMessageBuffer = nullptr;
	const DWORD length = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, ErrorCode, LANG_USER_DEFAULT, (LPSTR)&lpMessageBuffer, 0, NULL);
	if (length == 0) return "An error occured while getting error message.";
	auto scope = MakeInferiorScopeExit([lpMessageBuffer] { LocalFree(lpMessageBuffer); });
	DWORD i = length - 3;
	for (; '\r' != lpMessageBuffer[i] && '\n' != lpMessageBuffer[i] && '\0' != lpMessageBuffer[i]; i++);//改行文字削除
	lpMessageBuffer[i] = '\0';
	return lpMessageBuffer;
}

template<typename T, std::enable_if_t<std::is_integral_v<T> && !std::is_same_v<T, DWORD>, std::nullptr_t> = nullptr>
std::string GetErrorMessage(const T& ErrorCode) { return GetErrorMessage(static_cast<DWORD>(ErrorCode)); }


inline std::wstring GetRegistryKey(const HKEY& Root, const std::wstring& SubKey, const std::wstring& Key) {
	HKEY hKey = nullptr;
	if (const LSTATUS status = RegOpenKeyExW(Root, SubKey.c_str(), 0, KEY_QUERY_VALUE, &hKey); status != 0) throw std::runtime_error(GetErrorMessage(status));
	auto closer = MakeInferiorScopeExit([hKey] { RegCloseKey(hKey); });
	DWORD dwReadSize{}, dwKeyType{};
	if (const LSTATUS status = RegQueryValueExW(hKey, Key.c_str(), 0, &dwKeyType, nullptr, &dwReadSize)) throw std::runtime_error(GetErrorMessage(status));
	if (dwKeyType != REG_SZ && dwKeyType != REG_EXPAND_SZ) throw std::runtime_error("This key is not supported");
	std::wstring buffer{};
	buffer.resize(dwReadSize / sizeof(wchar_t));
	RegQueryValueExW(hKey, Key.c_str(), 0, nullptr, (LPBYTE)&buffer[0], &dwReadSize);
	buffer.resize(dwReadSize / sizeof(wchar_t) - 1);
	return buffer;
}

inline std::wstring GetUserProfileDirectory(const std::wstring& SID) {
	std::wstring Path = GetRegistryKey(HKEY_LOCAL_MACHINE, (L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\" + SID).c_str(), L"ProfileImagePath");
	Path += L"\\NTUSER.dat";
	return Path;
}

class NtUserDatHive {
public:
	HKEY m_hiveRoot;
	std::wstring m_hiveTarget;
	bool m_hived;
public:
	NtUserDatHive()
		: m_hiveRoot(), m_hiveTarget(), m_hived(false) {}
	NtUserDatHive(const std::wstring& SID, const HKEY& HiveRoot = HKEY_USERS, const std::wstring& HiveTarget = L"hive")
		: m_hiveRoot(HiveRoot), m_hiveTarget(HiveTarget), m_hived(false) {
		const std::wstring UserProfilePath = GetUserProfileDirectory(SID);
		if (!std::filesystem::exists(UserProfilePath)) throw std::runtime_error("User Profile is not found");
		if (LSTATUS status = RegLoadKey(HiveRoot, HiveTarget.c_str(), UserProfilePath.c_str()); status != ERROR_SUCCESS) throw std::runtime_error(GetErrorMessage(status));
		this->m_hived = true;
	}
	~NtUserDatHive() {
		if (this->m_hived) RegUnLoadKey(this->m_hiveRoot, this->m_hiveTarget.c_str());
	}
	HKEY GetHiveRoot() const noexcept { return this->m_hiveRoot; }
	std::wstring GetHiveTarget() const noexcept { return this->m_hiveTarget; }
};

inline std::wstring GetRegKeyData(const std::wstring& SID, const std::wstring& SubKeyTree, const std::wstring& Key) {
	const std::wstring RefKey = SID + L"\\" + SubKeyTree;
	return GetRegistryKey(HKEY_USERS, RefKey, Key);
}

inline std::wstring GetSIDString(const std::wstring& AccountName) {
	DWORD dwSidLen{};
	DWORD dwDomainLen{};
	SID_NAME_USE snu{}, tmpSnu{};

	// SIDの長さを取得する
	// この部分では関数は必ずエラーになるのでここでエラー判定して例外投げると処理が終わってしまう
	LookupAccountNameW(nullptr, AccountName.c_str(), nullptr, &dwSidLen, nullptr, &dwDomainLen, &tmpSnu);
	HANDLE ProcessHeap = GetProcessHeap();
	PSID psid = (PSID)HeapAlloc(ProcessHeap, 0, dwSidLen);
	auto ScopeSid = MakeInferiorScopeExit([ProcessHeap, psid] {HeapFree(ProcessHeap, 0, psid); });

	// 一時変数
	// これを第５引数に入れないとConvertSidToStringSidで落ちる(なぜ？)

	std::wstring szComputerNameBuf{};
	szComputerNameBuf.resize(dwDomainLen);

	// SIDを取得する
	// エラーIDはGetLastErrorで取れるので必要に応じてエラーメッセージ要更新
	LookupAccountNameW(nullptr, AccountName.c_str(), psid, &dwSidLen, &szComputerNameBuf[0], &dwDomainLen, &snu);
	if (psid == nullptr) throw std::runtime_error("Failed to get SID");

	// SIDを文字列として取得する

	LPTSTR lpBuf{};
	if (!ConvertSidToStringSid(psid, &lpBuf)) {
		throw std::runtime_error("Error in ConvertSidToStringSid Function" + GetErrorMessage(GetLastError()));
	}
	auto ScopeBuf = MakeInferiorScopeExit([lpBuf] { LocalFree(lpBuf); });
	return lpBuf;
}

inline std::vector<std::pair<std::wstring, std::wstring>> GetUserNameAndSids() {
	std::vector<std::pair<std::wstring, std::wstring>> Ret{};
	PVOID pv = nullptr;
	DWORD n, i = 1, err;
	do {
		err = NetQueryDisplayInformation(0, 1, i, MAXDWORD, MAX_PREFERRED_LENGTH, &n, &pv);
		auto scope = MakeInferiorScopeExit([pv] { NetApiBufferFree(pv); });
		switch (err) {
		case 0:
		case ERROR_MORE_DATA:
			if (n) {
				PNET_DISPLAY_USER p = (PNET_DISPLAY_USER)pv;
				do {
					try {
						const std::wstring AccountName = p->usri1_name;
						if (AccountName == L"DefaultAccount") continue;
						Ret.emplace_back(AccountName, GetSIDString(AccountName));
					}
					catch (const std::exception& er) {
						std::cout << er.what() << std::endl;
					}
				} while (p++, --n);
			}
			break;
		}
	} while (err == ERROR_MORE_DATA);
	return Ret;
}

inline void EnablePrivilege(const TCHAR* wpPrivilegeName, bool bEnable) {
	HANDLE hToken = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		throw std::runtime_error(GetErrorMessage(GetLastError()));
	}
	auto scope = MakeInferiorScopeExit([hToken] { ::CloseHandle( hToken ); });
	LUID tLuid{};
	if (!LookupPrivilegeValue(NULL, wpPrivilegeName, &tLuid)) throw std::runtime_error(GetErrorMessage(GetLastError()));
	TOKEN_PRIVILEGES TokenPrivileges{};
	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Luid = tLuid;
	TokenPrivileges.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
	if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TokenPrivileges), NULL, NULL))
		throw std::runtime_error(GetErrorMessage(GetLastError()));
}

int main() {
	try {
		const std::wstring LoadTargetSubKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders";
		const std::wstring LoadTargetKey = L"Personal";
		std::wcout.imbue(std::locale("Japanese"));
		EnablePrivilege(SE_RESTORE_NAME, true);
		const auto UserAndSidPairs = GetUserNameAndSids();
		for (const auto& i : UserAndSidPairs) {
			try {
				const LSTATUS status = [](const std::wstring& SID) {
					HKEY hKey = nullptr;
					const LSTATUS status = RegOpenKeyExW(HKEY_USERS, SID.c_str(), 0, KEY_QUERY_VALUE, &hKey);
					auto closer = MakeInferiorScopeExit([hKey] { RegCloseKey(hKey); });
					return status;
				}(i.second);
				if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND) throw std::runtime_error(GetErrorMessage(status));
				std::wcout << i.first << " : ";
				if (status != ERROR_FILE_NOT_FOUND) std::wcout << GetRegKeyData(i.second, LoadTargetSubKey, LoadTargetKey) << std::endl;
				else {
					const NtUserDatHive hiveNtUserDatHive(i.second);
					std::wcout << GetRegistryKey(hiveNtUserDatHive.GetHiveRoot(), hiveNtUserDatHive.GetHiveTarget() + L"\\" + LoadTargetSubKey, LoadTargetKey) << std::endl;
				}				
			}
			catch (const std::exception& er) {
				std::cout << er.what() << std::endl;
			}
		}
	}
	catch (...) {}
	return 0;
}
