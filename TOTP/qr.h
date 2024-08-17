#pragma once

#ifndef qrcodegen_BUFFER_LEN_MAX
#define qrcodegen_BUFFER_LEN_MAX  3918
#endif

HBITMAP QrFromData(_In_ const void* pv, _In_ ULONG cb, _Out_ ULONG* pxy);
HBITMAP QrFromDataT(_In_ PBYTE dataAndTemp, _In_ ULONG cb, _Out_ ULONG* pxy);
