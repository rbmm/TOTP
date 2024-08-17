#include "stdafx.h"

_NT_BEGIN

#include "util.h"

ULONG GetLastErrorEx()
{
	ULONG dwError = GetLastError();
	NTSTATUS status = RtlGetLastNtStatus();
	return RtlNtStatusToDosErrorNoTeb(status) == dwError ? HRESULT_FROM_NT(status) : dwError;
}

ULONG SecondsSince1970()
{
	union {
		LARGE_INTEGER time;
		FILETIME ft;
	};
	ULONG s;
	GetSystemTimeAsFileTime(&ft);
	RtlTimeToSecondsSince1970(&time, &s);

	return s;
}

extern const PCWSTR _s_ShaNames[] = {
	BCRYPT_SHA1_ALGORITHM, BCRYPT_SHA256_ALGORITHM, BCRYPT_SHA512_ALGORITHM
};

extern const UCHAR _s_ShaLens[] = { 20, 32, 64 };

NTSTATUS HMAC(_Out_ PULONG pn, _In_ SHM s, _In_ PBYTE pbSecret, _In_ ULONG cbSecret, _In_ INT D, _In_ ULONG P, _In_ ULONG64 T)
{
	return HMAC_I(pn, s, pbSecret, cbSecret, D, _byteswap_uint64(T / P));
}

NTSTATUS HMAC(_Out_ PULONG pn, _In_ SHM s, _In_ PBYTE pbSecret, _In_ ULONG cbSecret, _In_ INT D, ULONG64 T)
{
	return HMAC_I(pn, s, pbSecret, cbSecret, D, _byteswap_uint64(T));
}

NTSTATUS HMAC_I(_Out_ PULONG pn, _In_ SHM s, _In_ PBYTE pbSecret, _In_ ULONG cbSecret, _In_ INT D, _In_ ULONG64 T)
{
	*pn = 0;

	if (SHM::shaMAX <= s)
	{
		return STATUS_INVALID_PARAMETER_2;
	}

	PCWSTR pszAlgId = _s_ShaNames[static_cast<UCHAR>(s)];
	ULONG len = _s_ShaLens[static_cast<UCHAR>(s)];

	BCRYPT_ALG_HANDLE hAlgorithm;

	NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlgorithm, pszAlgId, 0, BCRYPT_ALG_HANDLE_HMAC_FLAG);

	if (0 <= status)
	{
		BCRYPT_HASH_HANDLE hHash;
		status = BCryptCreateHash(hAlgorithm, &hHash, 0, 0, pbSecret, cbSecret, 0);
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);

		if (0 <= status)
		{
			UCHAR hash[64];

			0 <= (status = BCryptHashData(hHash, (PBYTE)&T, sizeof(T), 0)) &&
				0 <= (status = BCryptFinishHash(hHash, hash, len, 0));

			BCryptDestroyHash(hHash);

			if (0 <= status)
			{
				ULONG n;
				memcpy(&n, &hash[hash[len - 1] & 0xF], 4);

				*pn = (_byteswap_ulong(n) & MAXLONG) % D;
			}
		}
	}

	return status;
}

BOOL BinToB32(_In_ PBYTE pb, _In_ ULONG cb, _Out_ PSTR psz, _In_ ULONG cch, _Out_ PULONG plen)
{
	if (!cb)
	{
		return FALSE;
	}

	ULONG n = (cb + 4) / 5;

	ULONG m = 1 + (n << 3);

	*plen = m;

	if (!psz)
	{
		return TRUE;
	}

	if (cch < m)
	{
		return FALSE;
	}

	m = ((5*n - cb) << 3)/5;
	do 
	{
		cch = min(cb, 5);
		ULONG64 u = 0, v = 0;
		memcpy((PBYTE)&u + 3, pb, cch);
		pb += 5, cb -= 5;
		u = _byteswap_uint64(u);
		cch = 8;
		do 
		{
			v <<= 8;
			v += "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[u & 0x1F];
			u >>= 5;
		} while (--cch);

		memcpy(psz, &v, 8);
		psz += 8;

	} while (--n);

	if (m)
	{
		memset(psz - m, '=', m);
	}

	*psz = 0;

	return TRUE;
}

BOOL B32ToBin(_In_ PCSTR str, _Out_ PBYTE pb, _In_ ULONG cb, _Out_ PULONG pcb)
{
	static const UCHAR _S_b32[] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
		0xff, 0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0xff, 0xff, 
		0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 
		0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff, 
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	};

	ULONG len = (ULONG)strlen(str);
	if (!len || (len & 7))
	{
		return FALSE;
	}

	len >>= 3;
	ULONG n = len * 5;
	*pcb = n;

	if (!pb)
	{
		return TRUE;
	}

	if (cb < n)
	{
		return FALSE;
	}

	ULONG UnusedBits = 0;
	do 
	{
		int i = 8;
		ULONG64 u = 0;
		do 
		{
			char c = _S_b32[*str++];

			if (0 > c)
			{
				if (1 == len && -0x80 == c)
				{
					UnusedBits += 5, c = 0;
				}
				else
				{
					return FALSE;
				}
			}

			u <<= 5;
			u += c;

		} while (--i);

		u = _byteswap_uint64(u);
		memcpy(pb, 3 + (PBYTE)&u, 5);
		pb += 5;

	} while (--len);

	if (UnusedBits)
	{
		*pcb -= 5 - (40 - UnusedBits)/8;
	}

	return TRUE;
}

extern const volatile UCHAR guz = 0;

NTSTATUS UserInfo::Create(UserInfo** ppUi)
{
	HANDLE hToken;

	NTSTATUS status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &hToken);

	if (0 <= status)
	{
		PVOID stack = alloca(guz);

		union {
			PVOID buf;
			PTOKEN_USER ptu;
		};

		ULONG cb = 0, rcb = sizeof(TOKEN_USER) + SECURITY_SID_SIZE(2 + SECURITY_NT_NON_UNIQUE_SUB_AUTH_COUNT);

		do
		{
			if (cb < rcb)
			{
				cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
			}

			status = NtQueryInformationToken(hToken, TokenUser, buf, cb, &rcb);

		} while (STATUS_BUFFER_TOO_SMALL == status);

		NtClose(hToken);

		if (0 <= status)
		{
			LSA_HANDLE hPolicy;
			OBJECT_ATTRIBUTES oa = { sizeof(oa) };
			if (0 <= (status = LsaOpenPolicy(0, &oa, POLICY_LOOKUP_NAMES, &hPolicy)))
			{
				PLSA_REFERENCED_DOMAIN_LIST ReferencedDomains = 0;
				PLSA_TRANSLATED_NAME Names = 0;
				PSID UserSid = ptu->User.Sid;

				status = LsaLookupSids2(hPolicy, 0, 1, &UserSid, &ReferencedDomains, &Names);

				LsaClose(hPolicy);

				if (0 <= status)
				{
					status = STATUS_INTERNAL_ERROR;

					UNICODE_STRING z = {};
					PCUNICODE_STRING DomainName = &z;
					ULONG DomainIndex = Names->DomainIndex;
					if (DomainIndex < ReferencedDomains->Entries)
					{
						DomainName = &ReferencedDomains->Domains[DomainIndex].Name;
					}

					ULONG cbSid = RtlLengthSid(UserSid);
					PWSTR name = 0;
					LONG cch = 0;
					UserInfo* pUi = 0;

					while (0 < (cch = _snwprintf(name, cch, L"%wZ@%wZ", &Names->Name, DomainName)))
					{
						if (name)
						{
							if (0 <= (status = RtlCopySid(cbSid, pUi, UserSid)))
							{
								*ppUi = pUi, pUi = 0;
							}

							break;
						}

						if (pUi = new(cbSid + ++cch * sizeof(WCHAR)) UserInfo)
						{
							name = (PWSTR)RtlOffsetToPointer(pUi, cbSid);
						}
						else
						{
							status = STATUS_NO_MEMORY;
							break;
						}
					}

					if (pUi)
					{
						delete pUi;
					}
				}

				LsaFreeMemory(Names);
				LsaFreeMemory(ReferencedDomains);
			}
		}
	}

	return status;
}

void AllowGetIcon(HWND hwnd)
{
	CHANGEFILTERSTRUCT r = { sizeof(r) };
	ChangeWindowMessageFilterEx(hwnd, WM_GETICON, MSGFLT_ALLOW, &r);
}

_NT_END