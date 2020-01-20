#include <windows.h>
#include <conio.h>
#include <stdio.h>
#include <winevt.h>

#pragma comment(lib, "wevtapi.lib")

void main(void)
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hResults = NULL;
    LPWSTR pwsPath = (wchar_t*)L"Microsoft-Windows-Sysmon/Operational";
    LPWSTR pwsQuery = (wchar_t*)L"*";

    hResults = EvtQuery(NULL, pwsPath, pwsQuery, EvtQueryChannelPath | EvtQueryReverseDirection);
    if (hResults == NULL)
    {
        status = GetLastError();
        if (status == ERROR_EVT_CHANNEL_NOT_FOUND) {
            wprintf(L"The channel was not found.\n");
        }
        else if (status == ERROR_EVT_INVALID_QUERY) {
            wprintf(L"The query is not valid.\n");
        }
        else {
            wprintf(L"EvtQuery() faild with %lu.\n", status);
        }

        goto cleanup;
    }

cleanup:
    if (hResults)
        EvtClose(hResults);
}