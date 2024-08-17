#include "stdafx.h"
#include "resource.h"
#include "qrcodegen.h"

_NT_BEGIN

#include "qr.h"

ULONG cv(ULONG i)
{
	return (i & ~7) + 7 - (i & 7);
}

HBITMAP QrFromDataT(_In_ PBYTE dataAndTemp, _In_ ULONG cb, _Out_ ULONG* pxy)
{
	UCHAR qrcode[qrcodegen_BUFFER_LEN_MAX]{};

	if (qrcodegen_encodeBinary(dataAndTemp, cb, qrcode, qrcodegen_Ecc_HIGH,
		qrcodegen_VERSION_MIN, qrcodegen_VERSION_MAX, qrcodegen_Mask_7, TRUE))
	{
		ULONG w = *qrcode, h = w;

		ULONG xy = 2*w;

		*pxy = xy;

		ULONG BytesPerLine = (((xy + 7) >> 3) + 3) & ~3, k = 8;
		ULONG s = BytesPerLine * xy;

		union {
			PUCHAR pbBits;
			PLONG Bits;
			PVOID pvBits;
		};

		struct BMI2 : BITMAPINFOHEADER 
		{
			ULONG bmiColors[2];
		} bmi = { 
			{ sizeof(BITMAPINFOHEADER), xy, xy, 1, 1, BI_RGB, s }, 
			{ 0x00FFFFFF } 
		};

		if (HBITMAP hbmp = CreateDIBSection(0, (BITMAPINFO*)&bmi, DIB_RGB_COLORS, &pvBits, 0, 0))
		{
			pbBits += s;

			do 
			{
				pbBits -= BytesPerLine;
				ULONG x = w, i = 0;
				do 
				{
					if (_bittest((PLONG)qrcode, k++))
					{
						_bittestandset(Bits, cv(2*i));
						_bittestandset(Bits, cv(2*i+1));
					}
				} while (i++, --x);

				pvBits = memcpy(pbBits - BytesPerLine, pbBits, BytesPerLine);

			} while (--h);

			return hbmp;
		}
	}

	return 0;
}

_NT_END