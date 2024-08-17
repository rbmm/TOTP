#include "stdafx.h"

_NT_BEGIN

#include "util.h"
#include "msgbox.h"
#include "persist.h"
#include "resource.h"

void OtpSetup(UserInfo* pUi, HWND hwnd);

void WINAPI ep(void*)
{
	UserInfo* pUi;

	NTSTATUS status;

	if (0 > (status = UserInfo::Create(&pUi)))
	{
		ShowErrorBox(0, HRESULT_FROM_NT(status), L"Get User Info Fail");
	}
	else
	{
		OtpSetup(pUi, 0);

		delete pUi;
	}

	ExitProcess(0);
}

_NT_END