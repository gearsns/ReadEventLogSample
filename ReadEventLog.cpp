// ReadEventLog.cpp : このファイルには 'main' 関数が含まれています。プログラム実行の開始と終了がそこで行われます。
//

#include <iostream>
#include <iomanip>
#include <windows.h>
#include <fstream>
#include <shlwapi.h>
#include "cppunzip.hpp"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "Shlwapi.lib")

static LPCTSTR EVENT_NAME_4624 = L"An account was successfully logged on.";
static LPCTSTR EVENT_NAME_4625 = L"An account failed to log on.";
static LPCTSTR EVENT_NAME_4771 = L"Kerberos pre-authentication failed.";
static LPCTSTR EVENT_NAME_4776 = L"The computer attempted to validate the credentials for an account.";

static void checkEventLog(LPCTSTR check_str, LPCTSTR filename, LPCTSTR dispfilename)
{
    HANDLE hEvent = OpenBackupEventLog(NULL, filename);
    if (NULL == hEvent)
    {
        return;
    }
    DWORD dwEventLogRecords;
    if (GetNumberOfEventLogRecords(hEvent, &dwEventLogRecords)) {
        std::cerr << "count:" << dwEventLogRecords << std::endl;
        const DWORD buffer_size = sizeof(EVENTLOGRECORD) * 1024;
        HANDLE hBuffer = GlobalAlloc(GPTR, buffer_size);
        if (hBuffer == NULL)
        {
            CloseEventLog(hEvent);
            return;
        }
        int len = lstrlen(check_str);
        LPBYTE buffer = (LPBYTE)GlobalLock(hBuffer);
        if (buffer == NULL)
        {
            return;
        }
        DWORD dwBytesRead = 0;
        DWORD dwMinNumberOfBytesNeeded = 0;
        while (ReadEventLog(hEvent, EVENTLOG_SEQUENTIAL_READ | EVENTLOG_FORWARDS_READ, 0, buffer, buffer_size, &dwBytesRead, &dwMinNumberOfBytesNeeded))
        {
            EVENTLOGRECORD* pEvtRec = reinterpret_cast<EVENTLOGRECORD*>(buffer);
            while (dwBytesRead > 0)
            {
                LPCTSTR lpszEvtSrc = (LPCTSTR)((PBYTE)pEvtRec + sizeof(EVENTLOGRECORD)); // イベントソース名
                if (pEvtRec->EventID == 4771 || pEvtRec->EventID == 4776 || pEvtRec->EventID == 46240 || pEvtRec->EventID == 4625)
                {
                    // この辺りで必要なイベントだけを対象に
                    /*
                        Windowsのログオン成功イベント : 4624
                        Windowsのログオン失敗イベント : 4625
                        Kerberos 事前認証に失敗しました。: 4771
                        コンピューターがアカウントの資格情報の確認を試行しました。 : 4776
                    */
                    LPCTSTR lpEventName = nullptr;
                    bool bFind = false;
                    LPCTSTR lpString = (LPCTSTR)((PBYTE)pEvtRec + pEvtRec->StringOffset);
                    int target_user = -1;
                    int target_ipadr = -1;
                    int target_workstation = -1;
                    int numStrings = pEvtRec->NumStrings;
                    if (pEvtRec->EventID == 4624)
                    {
                        target_user = 5;
                        target_ipadr = 18;
                        numStrings = 19;
                        lpEventName = EVENT_NAME_4624;
                        /*
                            0<Data Name="SubjectUserSid">S-1-5-18</Data>
                            1<Data Name="SubjectUserName">WIN-GG82ULGC9GO$</Data>
                            2<Data Name="SubjectDomainName">WORKGROUP</Data>
                            3<Data Name="SubjectLogonId">0x3e7</Data>
                            4<Data Name="TargetUserSid">S-1-5-21-1377283216-344919071-3415362939-500</Data>
                            5<Data Name="TargetUserName">Administrator</Data>
                            6<Data Name="TargetDomainName">WIN-GG82ULGC9GO</Data>
                            7<Data Name="TargetLogonId">0x8dcdc</Data>
                            8<Data Name="LogonType">2</Data>
                            9<Data Name="LogonProcessName">User32</Data>
                            0<Data Name="AuthenticationPackageName">Negotiate</Data>
                            1<Data Name="WorkstationName">WIN-GG82ULGC9GO</Data>
                            2<Data Name="LogonGuid">{00000000-0000-0000-0000-000000000000}</Data>
                            3<Data Name="TransmittedServices">-</Data>
                            4<Data Name="LmPackageName">-</Data>
                            5<Data Name="KeyLength">0</Data>
                            6<Data Name="ProcessId">0x44c</Data>
                            7<Data Name="ProcessName">C:\\Windows\\System32\\svchost.exe</Data>
                            8<Data Name="IpAddress">127.0.0.1</Data>
                            9<Data Name="IpPort">0</Data>
                            0<Data Name="ImpersonationLevel">%%1833</Data>
                            1<Data Name="RestrictedAdminMode">-</Data>
                            2<Data Name="TargetOutboundUserName">-</Data>
                            3<Data Name="TargetOutboundDomainName">-</Data>
                            4<Data Name="VirtualAccount">%%1843</Data>
                            5<Data Name="TargetLinkedLogonId">0x0</Data>
                            6<Data Name="ElevatedToken">%%1842</Data>
                        */
                    }
                    else if (pEvtRec->EventID == 4625)
                    {
                        target_user = 5;
                        numStrings = 6;
                        lpEventName = EVENT_NAME_4625;
                        /*
                             <Data Name="SubjectUserSid">S-1-5-18</Data>
                             <Data Name="SubjectUserName">DC01$</Data>
                             <Data Name="SubjectDomainName">CONTOSO</Data>
                             <Data Name="SubjectLogonId">0x3e7</Data>
                             <Data Name="TargetUserSid">S-1-0-0</Data>
                             <Data Name="TargetUserName">Auditor</Data>
                             <Data Name="TargetDomainName">CONTOSO</Data>
                             <Data Name="Status">0xc0000234</Data>
                             <Data Name="FailureReason">%%2307</Data>
                             <Data Name="SubStatus">0x0</Data>
                             <Data Name="LogonType">2</Data>
                             <Data Name="LogonProcessName">User32</Data>
                             <Data Name="AuthenticationPackageName">Negotiate</Data>
                             <Data Name="WorkstationName">DC01</Data>
                             <Data Name="TransmittedServices">-</Data>
                             <Data Name="LmPackageName">-</Data>
                             <Data Name="KeyLength">0</Data>
                             <Data Name="ProcessId">0x1bc</Data>
                             <Data Name="ProcessName">C:\\Windows\\System32\\winlogon.exe</Data>
                             <Data Name="IpAddress">127.0.0.1</Data>
                             <Data Name="IpPort">0</Data>
                        */
                    }
                    else if (pEvtRec->EventID == 4771)
                    {
                        target_user = 0;
                        target_ipadr = 6;
                        numStrings = 7;
                        lpEventName = EVENT_NAME_4771;
                        /*
                             <Data Name="TargetUserName">dadmin</Data>
                             <Data Name="TargetSid">S-1-5-21-3457937927-2839227994-823803824-1104</Data>
                             <Data Name="ServiceName">krbtgt/CONTOSO.LOCAL</Data>
                             <Data Name="TicketOptions">0x40810010</Data>
                             <Data Name="Status">0x10</Data>
                             <Data Name="PreAuthType">15</Data>
                             <Data Name="IpAddress">::ffff:10.0.0.12</Data>
                             <Data Name="IpPort">49254</Data>
                             <Data Name="CertIssuerName" />
                             <Data Name="CertSerialNumber" />
                             <Data Name="CertThumbprint" />
                        */
                    }
                    else if (pEvtRec->EventID == 4776)
                    {
                        target_user = 1;
                        target_workstation = 2;
                        numStrings = 3;
                        lpEventName = EVENT_NAME_4776;
                        /*
                             <Data Name="PackageName">MICROSOFT\_AUTHENTICATION\_PACKAGE\_V1\_0</Data>
                             <Data Name="TargetUserName">dadmin</Data>
                             <Data Name="Workstation">WIN81</Data>
                             <Data Name="Status">0xc0000234</Data>
                        */
                    }
                    if (pEvtRec->NumStrings < numStrings)
                    {
                        numStrings = pEvtRec->NumStrings;
                    }
                    if (target_user >= 0 || target_ipadr >= 0 || target_workstation >= 0)
                    {
                        for (int i = 0; i < numStrings; i++)
                        {
                            if (target_user == i || target_workstation == i)
                            {
                                if (lpString[0] == check_str[0] && StrCmpN(lpString, check_str, len) == 0) {
                                    bFind = true;
                                    break;
                                }
                            }
                            else if (target_ipadr == i)
                            {
                                if (lpString[0] == L':'
                                    && StrCmpN(lpString, L"::ffff:"/*IPV4*/, (sizeof(L"::ffff:") / sizeof(TCHAR)) - 1) == 0
                                    && StrCmpN(lpString + (sizeof(L"::ffff:") / sizeof(TCHAR)) - 1, check_str, len) == 0
                                    ) {
                                    bFind = true;
                                    break;
                                }
                            }
                            lpString += lstrlen(lpString) + 1;
                        }
                    }
                    if (bFind)
                    {
                        time_t t = pEvtRec->TimeGenerated; //イベント日時
                        struct tm local;
                        localtime_s(&local, &t);
                        //
                        std::wcout << dispfilename;
                        std::cout << "," << std::put_time(&local, "%Y-%m-%d %H:%M:%S") << ",";
                        std::wcout << pEvtRec->EventID << "," << lpEventName << ",";
                        lpString = (LPCTSTR)((PBYTE)pEvtRec + pEvtRec->StringOffset);
                        for (int i = 0; i < pEvtRec->NumStrings; i++)
                        {
                            std::wcout << "[" << i << "]" << lpString << ",";
                            lpString += lstrlen(lpString) + 1;
                        }
                        if (pEvtRec->DataLength)
                        {
                            //std::cout << (PSID)((PBYTE)pEvtRec + pEvtRec->DataOffset);
                        }
                        std::cout << std::endl;
                    }
                }

                dwBytesRead -= pEvtRec->Length;
                pEvtRec = (EVENTLOGRECORD*)((PBYTE)pEvtRec + pEvtRec->Length);
            }
        }
        GlobalFree(hBuffer);
    }
    CloseEventLog(hEvent);
}

using namespace cppunzip;

static std::wstring StringToWString(const std::string& str)
{
    // 変換に必要なサイズを取得
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), NULL, 0);
    // 変換先のwchar_t配列を作成
    std::wstring wstr(size_needed, 0);
    // 変換を実行
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), &wstr[0], size_needed);
    return wstr;
}

static bool ZipFolder(LPCTSTR check_str, LPCTSTR lpInZipFile)
{
    bool ret = true;

    try
    {
        std::ifstream is(lpInZipFile, std::ios::binary);
        IStreamFile f(is);
        UnZipper unzipper(f);
        for (auto& fileEntry : unzipper.listFiles()) {
            std::cerr << fileEntry.fileName() << ":" << std::endl;
            if (!fileEntry.isDir()) {
                std::vector<uint8_t> content = fileEntry.readContent();
                TCHAR filename[MAX_PATH] = {};
                GetTempFileName(L".", L"tmp", 0, filename);
                std::ofstream fout;
                fout.open(filename, std::ios::out | std::ios::binary | std::ios::trunc);
                if (fout)
                {
                    fout.write((char*)&content[0], content.size() * sizeof(content[0]));
                    fout.close();
                    std::wstring wfilename = StringToWString(fileEntry.fileName());
                    checkEventLog(check_str, filename, PathFindFileName(wfilename.c_str()));
                }
                DeleteFile(filename);
            }
        }
    }
    catch (...)
    {
        ret = false;
    }

    return ret;
}

static void Check(LPCTSTR check_str, LPCTSTR filename)
{
    if (PathIsDirectory(filename))
    {
        HANDLE hFind;
        WIN32_FIND_DATA win32fd;

        //拡張子の設定
        LPCTSTR dir_name = filename;
        TCHAR search_name[MAX_PATH] = {};
        swprintf_s(search_name, L"%s/*.evtx", dir_name);

        hFind = FindFirstFile(search_name, &win32fd);

        if (hFind == INVALID_HANDLE_VALUE) {
            return;
        }
        do {
            if (win32fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            }
            else {
                std::wcerr << win32fd.cFileName << std::endl;
                TCHAR filename[MAX_PATH] = {};
                swprintf_s(filename, L"%s/%s", dir_name, win32fd.cFileName);
                checkEventLog(check_str, filename, win32fd.cFileName);

            }
        } while (FindNextFile(hFind, &win32fd));

        FindClose(hFind);
        return;
    }
    LPCTSTR lpExt = PathFindExtension(filename);
    if (lpExt)
    {
        if (lstrcmpi(lpExt, L".zip") == 0)
        {
            ZipFolder(check_str, filename);
        }
        else if (lstrcmpi(lpExt, L".evtx") == 0)
        {
            checkEventLog(check_str, filename, PathFindFileName(filename));
        }
    }
}

int wmain(int argc, const wchar_t* argv[])
{
    if (argc <= 2)
    {
        return -1;
    }
    Check(argv[1], argv[2]);
}

// プログラムの実行: Ctrl + F5 または [デバッグ] > [デバッグなしで開始] メニュー
// プログラムのデバッグ: F5 または [デバッグ] > [デバッグの開始] メニュー

// 作業を開始するためのヒント: 
//    1. ソリューション エクスプローラー ウィンドウを使用してファイルを追加/管理します 
//   2. チーム エクスプローラー ウィンドウを使用してソース管理に接続します
//   3. 出力ウィンドウを使用して、ビルド出力とその他のメッセージを表示します
//   4. エラー一覧ウィンドウを使用してエラーを表示します
//   5. [プロジェクト] > [新しい項目の追加] と移動して新しいコード ファイルを作成するか、[プロジェクト] > [既存の項目の追加] と移動して既存のコード ファイルをプロジェクトに追加します
//   6. 後ほどこのプロジェクトを再び開く場合、[ファイル] > [開く] > [プロジェクト] と移動して .sln ファイルを選択します
