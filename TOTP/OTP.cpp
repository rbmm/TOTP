#include "stdafx.h"

_NT_BEGIN

#include "resource.h"
#include "qrcodegen.h"
#include "qr.h"
#include "util.h"
#include "msgbox.h"
#include "persist.h"
#include "wnd.h"

enum {
	IDC_CREATE = IDC_BUTTON1,
	IDC_CHECK = IDC_BUTTON2,
	IDC_DELETE = IDC_BUTTON3,

	IDC_SELECT_B32 = IDC_RADIO1,
	IDC_SELECT_HEX = IDC_RADIO2,

	IDC_IMPORT_B32 = IDC_BUTTON4,
	IDC_IMPORT_HEX = IDC_BUTTON5,

	IDC_OTP = IDC_EDIT1,
	IDC_B32 = IDC_EDIT2,
	IDC_HEX = IDC_EDIT3,

	IDC_ALGO = IDC_COMBO1,
	IDC_PERIOD = IDC_COMBO2,
	IDC_DIGITS = IDC_COMBO3,

	IDC_TIME = IDC_STATIC3,

	IDC_PREV_OTP = IDC_STATIC4,
	IDC_CUR_OTP = IDC_STATIC5,
	IDC_NEXT_OTP = IDC_STATIC6,

	IDC_LABEL = IDC_COMBO4,
	IDC_INFO = IDC_STATIC7,
};

BOOL IsValidChar(PCWSTR pcwz, ULONG n)
{
	// "QAZWSXEDCRFVTGBYHNUJMIKOLPqazwsxedcrfvtgbyhnujmikolp1234567890-=+$@~[](){}<>*!|.,\" ";
	static const LONG m[] = { 0x00000000, 0x73ff7f17, 0x2fffffff, 0x7ffffffe };
	do 
	{
		WORD c = *pcwz++;
		if (0x80 <= c || !_bittest(m, c))
		{
			return FALSE;
		}
	} while (--n);

	return TRUE;
}

LONG_PTR GetComboData(HWND hwndCB)
{
	LONG_PTR iItem = SendMessageW(hwndCB, CB_GETCURSEL, 0, 0);
	return 0 > iItem ? 0 : SendMessageW(hwndCB, CB_GETITEMDATA, iItem, 0);
}

class COtpDialog : public YDlg, MDC, TOTP
{
	UserInfo* _M_pUi;
	HICON _M_hi[2] = {};
	
	LONG _M_iToken = -1;
	ULONG _M_v = 0;
	ULONG _M_CurOtp = 0;
	ULONG _M_NextOtp = 0;

	ULONG _xy = 0;

	SHM _M_OtpAlgo;
	UCHAR _M_OtpDigits;
	UCHAR _M_OtpPeriod;
	WCHAR _M_Label[17];

	void OnPaint(HWND hwndDlg)
	{
		PAINTSTRUCT ps;
		if (BeginPaint(hwndDlg, &ps))
		{
			if (_M_hbmp)
			{
				GetWindowRect(GetDlgItem(hwndDlg, IDC_STATIC2), &ps.rcPaint);
				ScreenToClient(hwndDlg, (POINT*)&ps.rcPaint);
				RECT rc, rc2;
				GetWindowRect(GetDlgItem(hwndDlg, IDC_STATIC1), &rc);
				ScreenToClient(hwndDlg, (POINT*)&rc);
				GetWindowRect(GetDlgItem(hwndDlg, IDC_LABEL), &rc2);
				ScreenToClient(hwndDlg, 1 + (POINT*)&rc2);
				UINT xy = _xy;
				BitBlt(ps.hdc, (rc.left - xy) >> 1, (rc2.bottom + ps.rcPaint.top - xy) >> 1, xy, xy, _M_hMemDC, 0, 0, SRCCOPY);
			}
			EndPaint(hwndDlg, &ps);
		}
	}

	void SetB32Hex(HWND hwndDlg, PBYTE pbSecret, ULONG cbSecret, PCSTR b32)
	{
		SetDlgItemTextA(hwndDlg, IDC_B32, b32);

		WCHAR wz[129];
		ULONG n = _countof(wz);
		if (CryptBinaryToStringW(pbSecret, cbSecret, CRYPT_STRING_HEXRAW|CRYPT_STRING_NOCRLF, wz, &n))
		{
			SetDlgItemTextW(hwndDlg, IDC_HEX, wz);
		}
	}

	NTSTATUS ImportB32(HWND hwndDlg)
	{
		CHAR wz[130];
		if (UINT len = GetDlgItemTextA(hwndDlg, IDC_B32, wz, _countof(wz)))
		{
			if (128 < len)
			{
				return STATUS_NAME_TOO_LONG;
			}

			UCHAR secret[65];
			ULONG cb;
			if (B32ToBin(wz, secret, sizeof(secret), &cb))
			{
				return Import(hwndDlg, secret, cb);
			}

			return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
		}

		return STATUS_BUFFER_ALL_ZEROS;
	}

	NTSTATUS ImportHex(HWND hwndDlg)
	{
		WCHAR wz[130];
		if (UINT len = GetDlgItemTextW(hwndDlg, IDC_HEX, wz, _countof(wz)))
		{
			if (128 < len)
			{
				return STATUS_NAME_TOO_LONG;
			}

			UCHAR secret[sizeof(_M_secret)];
			ULONG cb = sizeof(secret);
			if (CryptStringToBinaryW(wz, len, CRYPT_STRING_HEXRAW, secret, &cb, 0, 0))
			{
				return Import(hwndDlg, secret, cb);
			}

			return HRESULT_FROM_WIN32(GetLastError());
		}

		return STATUS_BUFFER_ALL_ZEROS;
	}

	NTSTATUS Import(HWND hwndDlg, PBYTE pbSecret, ULONG cbSecret)
	{
		if (cbSecret < 16)
		{
			return STATUS_PWD_TOO_SHORT;
		}

		if (cbSecret != _M_cbSecret || memcmp(_M_secret, pbSecret, cbSecret) || 
			_M_OtpAlgo != _M_Algo ||
			_M_OtpPeriod != _M_Period ||
			_M_OtpDigits != _M_Digits)
		{
			return Create(hwndDlg, pbSecret, cbSecret);
		}

		return STATUS_SUCCESS;
	}

	NTSTATUS CreateNew(HWND hwndDlg)
	{
		UCHAR cbSecret = _s_ShaLens[static_cast<UCHAR>(_M_OtpAlgo)];
		UCHAR secret[sizeof(_M_secret)];
		NTSTATUS status = BCryptGenRandom(0, secret, cbSecret, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

		return 0 > status ? status : Create(hwndDlg, secret, cbSecret);
	}

	NTSTATUS Create(HWND hwndDlg, 
		PBYTE pbSecret, 
		ULONG cbSecret, 
		BOOL bNotSave = FALSE)
	{
		WCHAR szLabel[17];
		ULONG cch;
		NTSTATUS status = STATUS_OBJECT_NAME_INVALID;
		if (cch = GetDlgItemTextW(hwndDlg, IDC_LABEL, szLabel, _countof(szLabel)))
		{
			if (IsValidChar(szLabel, cch))
			{
				return Create(hwndDlg, szLabel, pbSecret, cbSecret, _M_OtpAlgo, _M_OtpPeriod, _M_OtpDigits, bNotSave);
			}

			status = STATUS_INVALID_EA_NAME;
		}

		SetFocus(GetDlgItem(hwndDlg, IDC_LABEL));
		return status;
	}

	NTSTATUS Create(HWND hwndDlg, 
		PCWSTR szLabel, 
		PBYTE pbSecret, 
		ULONG cbSecret, 
		SHM Algo,
		UCHAR Period,
		UCHAR Digits,
		BOOL bNotSave = FALSE)
	{
		if (sizeof(_M_secret) < cbSecret)
		{
			return STATUS_INVALID_PARAMETER;
		}

		PCWSTR pszAlgId = _s_ShaNames[static_cast<UCHAR>(Algo)];
		union {
			WCHAR wz[0x80];
			char ss[qrcodegen_BUFFER_LEN_MAX];
			TOTP totp;
		};

		INT i = sprintf_s(ss, _countof(ss), 
			"otpauth://totp/%ws:%ws?issuer=RBMM&algorithm=%ws&digits=%u&period=%u&secret=", 
			szLabel, _M_pUi->GetName(), pszAlgId, Digits, Period);

		if (0 < i)
		{
			ULONG cch;
			if (BinToB32(pbSecret, cbSecret, ss + i, _countof(ss) - i, &cch))
			{
				SetB32Hex(hwndDlg, pbSecret, cbSecret, ss + i);

				DbgPrint("%hs\n", ss);//$$

				if (HBITMAP hbmp = QrFromDataT((PUCHAR)ss, cch + i, &_xy))
				{
					totp.Type = TOTP::eTOTP;
					totp._M_Algo = Algo;
					totp._M_Period = Period;
					totp._M_Digits = Digits;
					totp._M_cbSecret = (UCHAR)cbSecret;
					memcpy(totp._M_secret, pbSecret, cbSecret);

					NTSTATUS status = bNotSave ? STATUS_SUCCESS : SaveTOTP(szLabel, &totp);

					if (0 <= status)
					{
						Set(hbmp);

						memcpy(static_cast<TOTP*>(this), &totp, sizeof(TOTP));
						wcscpy(_M_Label, szLabel);

						_M_CurOtp = 0;
						_M_NextOtp = 0;
						_M_v = 0;

						swprintf_s(wz, _countof(wz), L"%ws: %ws [%u] %us", szLabel, pszAlgId, _M_Digits, _M_Period);
						SetDlgItemTextW(hwndDlg, IDC_INFO, wz);

						INT iToken;
						if (0 > (iToken = (INT)SendDlgItemMessageW(hwndDlg, IDC_LABEL, CB_FINDSTRINGEXACT, 0, (LPARAM)szLabel)))
						{
							iToken = (INT)SendDlgItemMessageW(hwndDlg, IDC_LABEL, CB_ADDSTRING, 0, (LPARAM)szLabel);
						}

						_M_iToken = iToken;

						UpdateControls(hwndDlg, TRUE);

						OnTimer(hwndDlg);

						return STATUS_SUCCESS;
					}

					DeleteObject(hbmp);

					return status;
				}
			}
		}

		return STATUS_UNSUCCESSFUL;
	}

	ULONG Get_D()
	{
		ULONG D = 1000000;

		if (ULONG n = _M_Digits - 6)
		{
			do 
			{
				D *= 10;
			} while (--n);
		}

		return D;
	}

	void SetOtp( _In_ HWND hwndDlg, _In_ int nIDDlgItem, _In_ UINT uValue)
	{
		WCHAR sz[16], fmt[16];
		swprintf_s(fmt, _countof(fmt), L"%%0%uu", _M_OtpDigits);
		swprintf_s(sz, _countof(sz), fmt, uValue);
		SetDlgItemTextW(hwndDlg, nIDDlgItem, sz);
	}

	BOOL IsOtpOk(ULONG otp, ULONG v, ULONG D)
	{
		return 0 <= HMAC(&D, _M_OtpAlgo, _M_secret, _M_cbSecret, D, v) && D == otp;
	}

	NTSTATUS Check(HWND hwndDlg)
	{
		BOOL b;
		ULONG otp = GetDlgItemInt(hwndDlg, IDC_OTP, &b, FALSE);

		if (!b)
		{
			return ERROR_INVALID_DATA;
		}

		ULONG t = SecondsSince1970();
		ULONG p = _M_OtpPeriod;
		ULONG v = t / p, u;
		ULONG D = Get_D();

		if (IsOtpOk(otp, v, D))
		{
			return S_OK;
		}

		if (v != (u = (t - (p >> 2)) / p) && IsOtpOk(otp, u, D))
		{
			return S_OK;
		}

		if (v != (u = (t + (p >> 2)) / p) && IsOtpOk(otp, u, D))
		{
			return S_OK;
		}

		return STATUS_NOT_SAME_OBJECT;
	}

	void OnTimer(HWND hwndDlg)
	{
		if (_M_hbmp)
		{
			ULONG t = SecondsSince1970();
			ULONG v = t / _M_Period;

			WCHAR s[16];
			swprintf_s(s, _countof(s), L"%02u", (1 + v) * _M_Period - t);
			SetDlgItemTextW(hwndDlg, IDC_TIME, s);
			
			if (_M_v != v)
			{
				ULONG D = Get_D(), n;

				if (_M_v + 1 == v)
				{
					SetOtp(hwndDlg, IDC_PREV_OTP, _M_CurOtp);
					SetOtp(hwndDlg, IDC_CUR_OTP, _M_NextOtp);
					_M_CurOtp = _M_NextOtp;
				}
				else
				{
					if (0 <= HMAC(&n, _M_Algo, _M_secret, _M_cbSecret, D, v - 1))
					{
						SetOtp(hwndDlg, IDC_PREV_OTP, n);
					}

					if (0 <= HMAC(&n, _M_Algo, _M_secret, _M_cbSecret, D, v))
					{
						_M_CurOtp = n;
						SetOtp(hwndDlg, IDC_CUR_OTP, n);
					}
				}

				if (0 <= HMAC(&n, _M_Algo, _M_secret, _M_cbSecret, D, v + 1))
				{
					_M_NextOtp = n;
					SetOtp(hwndDlg, IDC_NEXT_OTP, n);
				}

				_M_v = v;
			}
		}
	}

	void UpdateControls(HWND hwndDlg, BOOL bEnable)
	{
		InvalidateRect(hwndDlg, 0, TRUE);
		EnableWindow(GetDlgItem(hwndDlg, IDC_DELETE), bEnable);
		EnableWindow(GetDlgItem(hwndDlg, IDC_CHECK), bEnable);
		EnableWindow(GetDlgItem(hwndDlg, IDC_OTP), bEnable);
	}

	void OnDelete(HWND hwndDlg)
	{
		INT i = (INT)SendDlgItemMessageW(hwndDlg, IDC_LABEL, CB_GETCURSEL, 0, 0);
		if (0 < i)
		{
			if (IDYES == CustomMessageBox(hwndDlg, L"Are you sure ?", L"Delete Token", MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2))
			{
				SendDlgItemMessageW(hwndDlg, IDC_LABEL, CB_DELETESTRING, i, 0);

				MDC::Set(0);

				UpdateControls(hwndDlg, FALSE);

				static const UINT s[] = { IDC_TIME, IDC_PREV_OTP, IDC_CUR_OTP, IDC_NEXT_OTP, IDC_HEX, IDC_B32, IDC_INFO, IDC_OTP };
				i = _countof(s);
				do 
				{
					SetDlgItemTextW(hwndDlg, s[--i], 0);
				} while (i);

				_M_cbSecret = 0;

				_M_iToken = -1;

				DeleteUserData(_M_Label);
			}
		}
	}

	BOOL OnInitDialog(HWND hwndDlg)
	{
		if (!MDC::Init())
		{
			EndDialog(hwndDlg, -1);
			return FALSE;
		}

		AllowGetIcon(hwndDlg);

		static const SHM _s_1[] = { SHM::sha512, SHM::sha256, SHM::sha1 };

		LPARAM lParam;
		ULONG n = _countof(_s_1);
		do 
		{
			lParam = static_cast<UCHAR>(_s_1[--n]);
			SendDlgItemMessageW(hwndDlg, IDC_ALGO, CB_SETITEMDATA, 
				SendDlgItemMessageW(hwndDlg, IDC_ALGO, CB_ADDSTRING, 0, (LPARAM)_s_ShaNames[lParam]), lParam + 1);
		} while (n);

		static const UINT _s_2[] = { 60, 30, 15 };

		WCHAR sz[16];
		n = _countof(_s_2);
		do 
		{
			lParam = (LPARAM)_s_2[--n];
			swprintf_s(sz, _countof(sz), L"%u", (ULONG)lParam);
			SendDlgItemMessageW(hwndDlg, IDC_PERIOD, CB_SETITEMDATA, 
				SendDlgItemMessageW(hwndDlg, IDC_PERIOD, CB_ADDSTRING, 0, (LPARAM)sz), lParam);
		} while (n);

		n = 3;
		do 
		{
			lParam = 9 - n;
			swprintf_s(sz, _countof(sz), L"%u", (ULONG)lParam);
			SendDlgItemMessageW(hwndDlg, IDC_DIGITS, CB_SETITEMDATA, 
				SendDlgItemMessageW(hwndDlg, IDC_DIGITS, CB_ADDSTRING, 0, (LPARAM)sz), lParam);
		} while (--n);

		static const UINT _s_3[] = { IDC_DIGITS, IDC_PERIOD, IDC_ALGO };
		UINT _s_4[] = { 0, 1, 0 };

		_M_Algo = SHM::shaMAX;
		_M_OtpAlgo = SHM::sha1;
		_M_OtpDigits = 6;
		_M_OtpPeriod = 30;
		InitCombo(hwndDlg, _s_4);

		SendDlgItemMessageW(hwndDlg, IDC_SELECT_B32, BM_SETCHECK, BST_CHECKED, 0);

		union {
			UCHAR buf[0x400];
			WCHAR wz[0x200];
		};

		if (0 < swprintf_s(wz, _countof(wz), L"OTP Parameters for %ws", _M_pUi->GetName()))
		{
			SetWindowTextW(hwndDlg, wz);
		}

		static const ULONG _s_x[] = { SM_CXSMICON, SM_CXICON };
		static const ULONG _s_y[] = { SM_CYSMICON, SM_CYICON };
		static const ULONG _s_t[] = { ICON_SMALL, ICON_BIG };

		n = _countof(_M_hi);
		do 
		{
			--n;
			HICON hi;
			if (0 <= LoadIconWithScaleDown((HINSTANCE)&__ImageBase, MAKEINTRESOURCEW(IDI_MAIN_ICO), 
				GetSystemMetrics(_s_x[n]), GetSystemMetrics(_s_y[n]), &hi))
			{
				_M_hi[n] = hi;
				SendMessage(hwndDlg, WM_SETICON, _s_t[n], (LPARAM)hi);
			}
		} while (n);

		InitComboFromRegistry(GetDlgItem(hwndDlg, IDC_LABEL));

		SetTimer(hwndDlg, 1, 1000, 0);

		return TRUE;
	}

	void SelectHexB32(HWND hwndDlg, UINT id1, UINT id2, UINT id3, UINT id4)
	{
		SendDlgItemMessageW(hwndDlg, id1, EM_SETREADONLY, TRUE, 0);
		ShowWindow(GetDlgItem(hwndDlg, id2), SW_HIDE);
		SendDlgItemMessageW(hwndDlg, id3, EM_SETREADONLY, FALSE, 0);
		ShowWindow(GetDlgItem(hwndDlg, id4), SW_SHOW);
	}

	void InitCombo(HWND hwndDlg, const UINT* pu)
	{
		static const UINT _s_3[] = { IDC_DIGITS, IDC_PERIOD, IDC_ALGO };

		ULONG n = _countof(_s_3);
		do 
		{
			--n;
			SendDlgItemMessageW(hwndDlg, _s_3[n], CB_SETCURSEL, pu[n], 0);
		} while (n);
	}

	void LoadToken(HWND hwndDlg, HWND hwndCB)
	{
		INT i = ComboBox_GetCurSel(hwndCB);
		if (0 <= i && i != _M_iToken)
		{
			WCHAR szLabel[17];
			if (ULONG len = ComboBox_GetLBTextLen(hwndCB, i))
			{
				if (len < _countof(szLabel))
				{
					if (0 < ComboBox_GetLBText(hwndCB, i, szLabel))
					{
						UCHAR buf[0x100];
						TOTP* pt;
						if (0 <= LoadTOTPData(szLabel, buf, sizeof(buf), &pt))
						{
							if (NTSTATUS status = Create(hwndDlg, szLabel, pt->_M_secret, pt->_M_cbSecret, 
								pt->_M_Algo, pt->_M_Period, pt->_M_Digits, TRUE))
							{
								ShowErrorBox(hwndDlg, status, L"Load Token");
							}
							else
							{
								_M_OtpAlgo = _M_Algo;
								_M_OtpPeriod = _M_Period;
								_M_OtpDigits = _M_Digits;

								_M_iToken = i;
								UINT _s_4[] = { _M_Digits - 6, (_M_Period/15) >> 1, (UCHAR)_M_Algo - (UCHAR)SHM::sha1 };

								InitCombo(hwndDlg, _s_4);
							}
						}
						else
						{
							DeleteUserData(szLabel);
						}
					}
				}
			}
		}
	}

	virtual INT_PTR DlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		switch (uMsg)
		{
		//case WM_GETICON:
		//	switch (wParam)
		//	{
		//	case ICON_BIG:
		//		return (INT_PTR)_M_hi[1];
		//	case ICON_SMALL:
		//	case ICON_SMALL2:
		//		return (INT_PTR)_M_hi[0];
		//	}
		//	break;
		case WM_COMMAND:
			switch (wParam)
			{
			case IDCANCEL:
				EndDialog(hwndDlg, 0);
				break;

			case IDC_CREATE:
				if (uMsg = CreateNew(hwndDlg))
				{
					ShowErrorBox(hwndDlg, uMsg, L"Create New Token");
				}
				break;
			
			case IDC_IMPORT_HEX:
				if (uMsg = ImportHex(hwndDlg))
				{
					ShowErrorBox(hwndDlg, uMsg, L"Import Hex Data");
				}
				break;

			case IDC_IMPORT_B32:
				if (uMsg = ImportB32(hwndDlg))
				{
					ShowErrorBox(hwndDlg, uMsg, L"Import Base32 Data");
				}
				break;

			case IDC_CHECK:
				ShowErrorBox(hwndDlg, Check(hwndDlg), L"Check OTP");
				break;

			case IDC_DELETE:
				OnDelete(hwndDlg);
				break;

			case IDC_SELECT_B32:
				SelectHexB32(hwndDlg, IDC_HEX, IDC_IMPORT_HEX, IDC_B32, IDC_IMPORT_B32);
				break;

			case IDC_SELECT_HEX:
				SelectHexB32(hwndDlg, IDC_B32, IDC_IMPORT_B32, IDC_HEX, IDC_IMPORT_HEX);
				break;

			case MAKEWPARAM(IDC_DIGITS, CBN_SELCHANGE):
				if (wParam = GetComboData((HWND)lParam))
				{
					if (wParam - 6 < 3)
					{
						_M_OtpDigits = (UCHAR)wParam;
					}
				}
				break;

			case MAKEWPARAM(IDC_PERIOD, CBN_SELCHANGE):
				if (wParam = GetComboData((HWND)lParam))
				{
					if (wParam - 15 <= 60 - 15)
					{
						_M_OtpPeriod = (UCHAR)wParam;
					}
				}
				break;

			case MAKEWPARAM(IDC_ALGO, CBN_SELCHANGE):
				if (wParam = GetComboData((HWND)lParam))
				{
					if (--wParam < (UCHAR)SHM::shaMAX)
					{
						_M_OtpAlgo = (SHM)wParam;
					}
				}
				break;

			case MAKEWPARAM(IDC_LABEL, CBN_SELCHANGE):
				LoadToken(hwndDlg, (HWND)lParam);
				break;
			}
			break;

		case WM_NCDESTROY:
			MDC::Destroy();
			if (_M_hi[1])DestroyIcon(_M_hi[1]);
			if (_M_hi[0])DestroyIcon(_M_hi[0]);
			break;

		case WM_PAINT:
			OnPaint(hwndDlg);
			return 0;

		case WM_TIMER:
			if (1 == wParam)
			{
				OnTimer(hwndDlg);
			}
			break;
		}

		return __super::DlgProc(hwndDlg, uMsg, wParam, lParam);
	}

public:

	COtpDialog(UserInfo* pUi) : _M_pUi(pUi)
	{
	}
};

void OtpSetup(UserInfo* pUi, HWND hwnd)
{
	COtpDialog dlg(pUi);
	dlg.DoModal((HINSTANCE)&__ImageBase, MAKEINTRESOURCEW(IDD_DIALOG2), hwnd);
}

_NT_END