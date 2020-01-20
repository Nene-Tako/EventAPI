#include <windows.h>
#include <conio.h>
#include <stdio.h>
#include <winevt.h>

#pragma comment(lib, "wevtapi.lib")
DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent);
DWORD PrintEvent(EVT_HANDLE hEvent);

void main(void)
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hSubscription = NULL;
    LPWSTR pwsPath = (wchar_t *)L"Microsoft-Windows-Sysmon/Operational";
    LPWSTR pwsQuery = (wchar_t *)L"*";

    hSubscription = EvtSubscribe(NULL, NULL, pwsPath, pwsQuery, NULL, NULL,
        SubscriptionCallback, EvtSubscribeStartAtOldestRecord);
    if (hSubscription == NULL)
    {
        status = GetLastError();

        if (status = ERROR_EVT_CHANNEL_NOT_FOUND)
            wprintf(L"Channel %s was not found.\n", pwsPath);
        else if (status == ERROR_EVT_INVALID_QUERY)
            wprintf(L"The query \"%s\" is not valid.\n", pwsQuery);
        else
            wprintf(L"EvtSubscribe failed with %lu.\n", status);

        goto cleanup;
    }
    wprintf(L"Hit any key to quit\n");
    while (!_kbhit())
        Sleep(10);
cleanup:
    if (hSubscription)
        EvtClose(hSubscription);
}

DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent)
{
    UNREFERENCED_PARAMETER(pContext);

    DWORD status = ERROR_SUCCESS;

    switch (action)
    {
    case EvtSubscribeActionError:
        if ((DWORD)hEvent == ERROR_EVT_QUERY_RESULT_STALE)
        {
            wprintf(L"The subscription callback was notified that event records are missing.\n");
        }
        else
        {
            wprintf(L"The subscription callback received the following Win32 error: %lu\n", (DWORD)hEvent);
        }
        break;
    case EvtSubscribeActionDeliver:
        if ((status == PrintEvent(hEvent)) != ERROR_SUCCESS)
        {
            goto cleanup;
        }
        break;
    default:
        wprintf(L"SubscriptionCallback: Unknown action.\n");
    }
cleanup:
    if (ERROR_SUCCESS != status) { }
    return status;
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