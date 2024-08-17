#pragma once

struct MDC 
{
	HDC _M_hMemDC = 0;
	HBITMAP _M_hbmp = 0;
	HGDIOBJ _M_ho = 0;

	void Set(HBITMAP hbmp);

	void Destroy();

	BOOL Init();

	~MDC();
};

class YDlg
{
	LONG _M_dwRef = 1;
	LONG _M_msgCount = 1 << 31;

	virtual void AfterLastMessage()
	{
	}

	virtual BOOL OnInitDialog(HWND /*hwnd*/)
	{
		return TRUE;
	}

	static INT_PTR CALLBACK _S_DlgProc(HWND hwnd, UINT umsg, WPARAM wParam, LPARAM lParam);

	static INT_PTR CALLBACK DlgProcStart(HWND hwnd, UINT umsg, WPARAM /*wParam*/, LPARAM lParam);

protected:

	virtual INT_PTR DlgProc(HWND /*hwnd*/, UINT umsg, WPARAM /*wParam*/, LPARAM /*lParam*/);

public:

	virtual ~YDlg()
	{

	}

	void AddRef()
	{
		InterlockedIncrementNoFence(&_M_dwRef);
	}

	void Release()
	{
		if (!InterlockedDecrement(&_M_dwRef))
		{
			delete this;
		}
	}

	INT_PTR DoModal(HINSTANCE hInstance, PCWSTR lpTemplateName, HWND hWndParent)
	{
		return DialogBoxParam(hInstance, lpTemplateName, hWndParent, DlgProcStart, (LPARAM)this);
	}
};