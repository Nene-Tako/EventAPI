#include <windows.h>
#include <conio.h>
#include <stdio.h>
#include <winevt.h>

#pragma comment(lib, "wevtapi.lib")
DWORD PrintEvent(EVT_HANDLE hEvent);
DWORD PrintResults(EVT_HANDLE hResults);
void main(void)
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hResults = NULL;
    LPWSTR pwsPath = (wchar_t*)L"Microsoft-Windows-Sysmon/Operational";
    LPWSTR pwsQuery = (wchar_t*)L"Event/System[EventID=3]";

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
    PrintResults(hResults);

cleanup:
    if (hResults)
        EvtClose(hResults);
}

DWORD PrintEvent(EVT_HANDLE hEvent)
{
    DWORD status = ERROR_SUCCESS;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
    LPWSTR pRenderedContent = NULL;

    if (!EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount))
    {
        if (ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
        {
            dwBufferSize = dwBufferUsed;
            pRenderedContent = (LPWSTR)malloc(dwBufferSize);
            if (pRenderedContent)
            {
                EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount);
            }
            else
            {
                wprintf(L"malloc failed\n");
                status = ERROR_OUTOFMEMORY;
                goto cleanup;
            }
        }

        if (ERROR_SUCCESS != (status = GetLastError()))
        {
            wprintf(L"EvtRender failed with %d\n", GetLastError());
            goto cleanup;
        }
    }

    wprintf(L"\n\n%s", pRenderedContent);

cleanup:

    if (pRenderedContent)
        free(pRenderedContent);

    return status;
}
DWORD PrintResults(EVT_HANDLE hResults)
{
    DWORD status = ERROR_SUCCESS;
    static const int arraySize = 10;

    DWORD returned = 0;
    EVT_HANDLE events[arraySize] = { 0 };
    bool run = true;

    while (run)
    {
        if (!EvtNext(hResults, arraySize, events, INFINITE, 0, &returned))
            break;
        for (DWORD i = 0; i < returned; i++)
        {
            status = PrintEvent(events[i]);
            if (status == ERROR_SUCCESS)
            {
                if (events[i] != nullptr)
                    EvtClose(events[i]);
                events[i] = nullptr;
            }
            else
            {
                run = false;
                break;
            }
        }
    }
    for (DWORD i = 0; i < returned; i++)
    {
        if (events[i] != nullptr)
            EvtClose(events[i]);
    }
    return status;
}