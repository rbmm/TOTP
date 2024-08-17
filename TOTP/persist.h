#pragma once

struct OFF_HEADER 
{
	enum { eFIDO = 'ODIF', eTOTP = 'PTOT' } Type;
	ULONG crc;
};

struct TOTP : OFF_HEADER 
{
	SHM _M_Algo;
	UCHAR _M_Digits;
	UCHAR _M_Period;
	UCHAR _M_cbSecret;
	UCHAR _M_secret[64];
};

NTSTATUS LoadTOTPData(PCWSTR Name, PBYTE pb, ULONG cb, _Out_ TOTP** ppt);

NTSTATUS SaveTOTP(PCWSTR Name, TOTP* pt);

NTSTATUS DeleteUserData(PCWSTR Name);

void InitComboFromRegistry(HWND hwndCB);