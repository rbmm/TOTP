#include "stdafx.h"

_NT_BEGIN

#include "util.h"
#include "persist.h"

NTSTATUS OpenKey(_Out_ PHANDLE KeyHandle, _In_ ACCESS_MASK DesiredAccess)
{
	UNICODE_STRING RegistryPath;
	NTSTATUS status = RtlFormatCurrentUserKeyPath(&RegistryPath);

	if (0 <= status)
	{
		PWSTR buf = 0;
		ULONG cch = 0;

		status = STATUS_INTERNAL_ERROR;

		while (cch = _snwprintf(buf, cch, L"%wZ\\rbmm", &RegistryPath))
		{
			if (buf)
			{
				status = STATUS_SUCCESS;
				break;
			}

			buf = (PWSTR)alloca(++cch * sizeof(WCHAR));
		}

		RtlFreeUnicodeString(&RegistryPath);

		RtlInitUnicodeString(&RegistryPath, buf);

		OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &RegistryPath, OBJ_CASE_INSENSITIVE };

		return ZwCreateKey(KeyHandle, DesiredAccess, &oa, 0, 0, 0, 0);
	}

	return status;
}

NTSTATUS DeleteUserData(PCWSTR Name)
{
	HANDLE hKey;

	NTSTATUS status = OpenKey(&hKey, KEY_WRITE);

	if (0 <= status)
	{
		UNICODE_STRING ObjectName;
		RtlInitUnicodeString(&ObjectName, Name);
		status = ZwDeleteValueKey(hKey, &ObjectName);

		NtClose(hKey);
	}

	return status;
}

NTSTATUS SaveUserData(PCWSTR Name, OFF_HEADER* ph, ULONG cb)
{
	ph->crc = 0;
	ph->crc = RtlComputeCrc32(0, ph, cb);

	HANDLE hKey;

	NTSTATUS status = OpenKey(&hKey, KEY_WRITE);

	if (0 <= status)
	{
		UNICODE_STRING ObjectName;
		RtlInitUnicodeString(&ObjectName, Name);
		status = ZwSetValueKey(hKey, &ObjectName, 0, REG_BINARY, ph, cb);

		NtClose(hKey);
	}

	return status;
}

NTSTATUS SaveTOTP(PCWSTR Name, TOTP* pt)
{
	ULONG cb = FIELD_OFFSET(TOTP, _M_secret) + pt->_M_cbSecret;

	return 0x400 < cb ? STATUS_EA_TOO_LARGE : SaveUserData(Name, pt, cb);
}

NTSTATUS IsDataValid(ULONG Type, ULONG DataLength, PVOID Data, _Out_ OFF_HEADER** pph, _Out_ PULONG pcb)
{
	if (REG_BINARY == Type)
	{
		if (sizeof(OFF_HEADER) < DataLength)
		{
			ULONG crc = reinterpret_cast<OFF_HEADER*>(Data)->crc;

			reinterpret_cast<OFF_HEADER*>(Data)->crc = 0;

			if (RtlComputeCrc32(0, Data, DataLength) == crc)
			{
				*pph = reinterpret_cast<OFF_HEADER*>(Data);
				*pcb = DataLength;
				return STATUS_SUCCESS;
			}
		}
	}

	return STATUS_BAD_DATA;
}

NTSTATUS LoadUserData(_In_ PCWSTR Name, _In_ PBYTE pb, _In_ ULONG cb, _Out_ OFF_HEADER** pph, _Out_ PULONG pcb)
{
	HANDLE hKey;

	NTSTATUS status = OpenKey(&hKey, KEY_READ);

	if (0 <= status)
	{
		UNICODE_STRING ObjectName;
		RtlInitUnicodeString(&ObjectName, Name);
		
		status = ZwQueryValueKey(hKey, &ObjectName, KeyValuePartialInformationAlign64, pb, cb, &cb);

		NtClose(hKey);

		if (0 <= status)
		{
			return IsDataValid(
				reinterpret_cast<PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64>(pb)->Type, 
				reinterpret_cast<PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64>(pb)->DataLength, 
				reinterpret_cast<PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64>(pb)->Data, 
				pph, pcb);
		}
	}

	return status;
}

NTSTATUS IsTotpValid(TOTP* pt, ULONG cb)
{
	if (OFF_HEADER::eTOTP == pt->Type)
	{
		if (FIELD_OFFSET(TOTP, _M_secret) < cb)
		{
			if (pt->_M_cbSecret == (cb - FIELD_OFFSET(TOTP, _M_secret)))
			{
				if (pt->_M_cbSecret <= 64)
				{
					if (pt->_M_Algo < SHM::shaMAX)
					{
						if (pt->_M_Digits - 6 < 9 - 6)
						{
							switch (pt->_M_Period)
							{
							case 15:
							case 30:
							case 60:
								return STATUS_SUCCESS;
							}
						}
					}
				}
			}
		}
	
		return STATUS_BAD_DATA;
	}

	return STATUS_OBJECT_TYPE_MISMATCH;
}

NTSTATUS LoadTOTPData(PCWSTR Name, PBYTE pb, ULONG cb, _Out_ TOTP** ppt)
{
	union {
		OFF_HEADER* ph;
		TOTP* pt;
	};

	NTSTATUS status = LoadUserData(Name, pb, cb, &ph, &cb);

	if (0 <= status)
	{
		if (0 <= (status = IsTotpValid(pt, cb)))
		{
			*ppt = pt;
		}
	}

	return status;
}

void InitComboFromRegistry(HWND hwndCB)
{
	HANDLE hKey;

	NTSTATUS status = OpenKey(&hKey, KEY_READ);

	if (0 <= status)
	{
		ULONG i = 0;
		union {
			UCHAR buf[0x80];
			KEY_VALUE_FULL_INFORMATION kvfi;
		};
		ULONG cb;
		do 
		{
			if (0 <= (status = ZwEnumerateValueKey(hKey, i++, KeyValueFullInformation, buf, sizeof(buf), &cb)))
			{
				union {
					OFF_HEADER* ph;
					TOTP* pt;
				};

				if (kvfi.NameLength && kvfi.NameLength <= 16 * sizeof(WCHAR) &&
					0 <= IsDataValid(kvfi.Type, kvfi.DataLength, buf + kvfi.DataOffset, &ph, &cb) &&
					0 <= IsTotpValid(pt, cb))
				{
					*(WCHAR*)RtlOffsetToPointer(kvfi.Name, kvfi.NameLength) = 0;
					ComboBox_AddString(hwndCB, kvfi.Name);
				}
			}
		} while (STATUS_NO_MORE_ENTRIES != status);
	}
}

_NT_END