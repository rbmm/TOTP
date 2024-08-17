#pragma once

ULONG GetLastErrorEx();

template <typename T> 
T HR(HRESULT& hr, T t)
{
	hr = t ? NOERROR : GetLastErrorEx();
	return t;
}

inline HRESULT EncodeObject(_In_ PCSTR lpszStructType, _In_ const void *pvStructInfo, _Out_ BYTE** ppbEncoded, _Inout_ ULONG *pcbEncoded)
{
	return GetLastHr(CryptEncodeObjectEx(X509_ASN_ENCODING, lpszStructType, 
		pvStructInfo, CRYPT_ENCODE_ALLOC_FLAG|CRYPT_ENCODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG, 0, ppbEncoded, pcbEncoded));
}

inline HRESULT EncodeObject(_In_ PCSTR lpszStructType, _In_ const void *pvStructInfo, _Out_ PDATA_BLOB blob)
{
	return EncodeObject(lpszStructType, pvStructInfo, &blob->pbData, &blob->cbData);
}

inline HRESULT Decode(_In_ PCSTR lpszStructType, _In_ PBYTE pb, _In_ ULONG cb, _Out_ void* ppv, _Out_opt_ PULONG pcb = 0)
{
	return CryptDecodeObjectEx(X509_ASN_ENCODING, lpszStructType, pb, cb,
		CRYPT_DECODE_ALLOC_FLAG|
		CRYPT_DECODE_NOCOPY_FLAG|
		CRYPT_DECODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG|
		CRYPT_DECODE_SHARE_OID_STRING_FLAG, 
		0, ppv, pcb ? pcb : &cb) ? S_OK : HRESULT_FROM_WIN32(GetLastError());
}

inline HRESULT Decode(_In_ PCSTR lpszStructType, _In_ PCRYPT_DATA_BLOB pdb, _Out_ void* ppv, _Out_opt_ PULONG pcb = 0)
{
	return Decode(lpszStructType, pdb->pbData, pdb->cbData, ppv, pcb);
}

inline HRESULT Decode(_In_ PCSTR lpszStructType, _In_ PCRYPT_BIT_BLOB pdb, _Out_ void* ppv, _Out_opt_ PULONG pcb = 0)
{
	return Decode(lpszStructType, pdb->pbData, pdb->cbData, ppv, pcb);
}

enum class SHM : UCHAR { sha1, sha256, sha512, shaMAX };

extern const PCWSTR _s_ShaNames[];
extern const UCHAR _s_ShaLens[];

ULONG SecondsSince1970();

NTSTATUS HMAC_I(_Out_ PULONG pn, _In_ SHM s, _In_ PBYTE pbSecret, _In_ ULONG cbSecret, _In_ INT D, ULONG64 T);

NTSTATUS HMAC(_Out_ PULONG pn, _In_ SHM s, _In_ PBYTE pbSecret, _In_ ULONG cbSecret, _In_ INT D, ULONG64 T);

NTSTATUS HMAC(_Out_ PULONG pn, _In_ SHM s, _In_ PBYTE pbSecret, _In_ ULONG cbSecret, _In_ INT D, _In_ ULONG P, _In_ ULONG64 T);

BOOL BinToB32(_In_ PBYTE pb, _In_ ULONG cb, _Out_ PSTR psz, _In_ ULONG cch, _Out_ PULONG plen);

BOOL B32ToBin(_In_ PCSTR str, _Out_ PBYTE pb, _In_ ULONG cb, _Out_ PULONG pcb);


inline ULONG RidFromSid(PSID Sid)
{
	return *RtlSubAuthoritySid(Sid, *RtlSubAuthorityCountSid(Sid) - 1);
}

struct UserInfo 
{
	inline PSID GetSid()
	{
		return this;
	}

	inline ULONG GetRid()
	{
		return RidFromSid(this);
	}

	inline PCWSTR GetName()
	{
		return (PCWSTR)RtlOffsetToPointer(this, RtlLengthSid(this));
	}

	static NTSTATUS Create(UserInfo** ppUi);

	void* operator new(size_t , ULONG s)
	{
		return LocalAlloc(LMEM_FIXED, s);
	}

	void operator delete(void* pv)
	{
		LocalFree(pv);
	}
};

extern volatile const UCHAR guz;

void AllowGetIcon(HWND hwnd);