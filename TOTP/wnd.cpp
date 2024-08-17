#include "stdafx.h"

_NT_BEGIN
#include "qrcodegen.h"
#include "qr.h"
#include "util.h"
//#include "msgbox.h"
#include "persist.h"
#include "wnd.h"
#include "resource.h"

BOOL MDC::Init()
{
	return 0 != (_M_hMemDC = CreateCompatibleDC(0));
}

void MDC::Set(HBITMAP hbmp)
{
	if (_M_hbmp)
	{
		SelectObject(_M_hMemDC, _M_ho), _M_ho = 0;
		DeleteObject(_M_hbmp), _M_hbmp = 0;
	}

	if (hbmp)
	{
		_M_hbmp = hbmp;
		_M_ho = SelectObject(_M_hMemDC, hbmp);
	}
}

void MDC::Destroy()
{
	Set(0);

	if (_M_hMemDC)
	{
		DeleteDC(_M_hMemDC), _M_hMemDC = 0;
	}
}

MDC::~MDC()
{
	Destroy();
}

INT_PTR CALLBACK YDlg::_S_DlgProc(HWND hwnd, UINT umsg, WPARAM wParam, LPARAM lParam)
{
	YDlg* dlg = reinterpret_cast<YDlg*>(GetWindowLongPtrW(hwnd, DWLP_USER));

	dlg->_M_msgCount++;

	lParam = dlg->DlgProc(hwnd, umsg, wParam, lParam);

	if (!--dlg->_M_msgCount)
	{
		dlg->AfterLastMessage();
		dlg->Release();
	}

	return lParam;
}

INT_PTR CALLBACK YDlg::DlgProcStart(HWND hwnd, UINT umsg, WPARAM /*wParam*/, LPARAM lParam)
{
	if (WM_INITDIALOG == umsg)
	{
		SetWindowLongPtrW(hwnd, DWLP_USER, lParam);
		SetWindowLongPtrW(hwnd, DWLP_DLGPROC, (LPARAM)_S_DlgProc);
		reinterpret_cast<YDlg*>(lParam)->AddRef();
		return reinterpret_cast<YDlg*>(lParam)->OnInitDialog(hwnd);
	}

	return 0;
}

INT_PTR YDlg::DlgProc(HWND /*hwnd*/, UINT umsg, WPARAM /*wParam*/, LPARAM /*lParam*/)
{
	switch (umsg)
	{
	case WM_NCDESTROY:
		_bittestandreset(&_M_msgCount, 31);
		break;
	}

	return 0;
}

_NT_END