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

static void checkEventLog(LPCTSTR filename)
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
                    TCHAR lpEventName[512] = {};
                    bool bFind = false;
                    LPCTSTR lpString = (LPCTSTR)((PBYTE)pEvtRec + pEvtRec->StringOffset);
                    int target = -1;
                    if (pEvtRec->EventID == 4624)
                    {
                        target = 5;
                        lstrcpy(lpEventName, L"An account was successfully logged on.");
                    }
                    else if (pEvtRec->EventID == 4771)
                    {
                        target = 0;
                        lstrcpy(lpEventName, L"Kerberos pre-authentication failed.");
                    }
                    else if (pEvtRec->EventID == 4776)
                    {
                        target = 1;
                        lstrcpy(lpEventName, L"The computer attempted to validate the credentials for an account.");
                    }
                    else if (pEvtRec->EventID == 4625)
                    {
                        target = 5;
                        lstrcpy(lpEventName, L"An account failed to log on.");
                    }
                    // ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★
                    // TargetUserNameが'AA'で始まる物を対象
                    // この辺を適当に変える!!
                    // ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★
                    for (int i = 0; i < pEvtRec->NumStrings; i++)
                    {
                        if (target == i)
                        {
                            if (lpString[0] == L'A' && lpString[1] == L'A') {
                                bFind = true;
                            }
                            break;
                        }
                        lpString += lstrlen(lpString) + 1;
                    }
                    if (bFind)
                    {
                        time_t t = pEvtRec->TimeGenerated; //イベント日時
                        struct tm local;
                        localtime_s(&local, &t);
                        //
                        std::wcout << pEvtRec->EventID << "[" << lpEventName << "],";
                        std::cout << std::put_time(&local, "%Y-%m-%d %H:%M:%S") << ",";
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

static bool ZipFolder(LPCTSTR lpInZipFile)
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
                    checkEventLog(filename);
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

static void Check(LPCTSTR filename)
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
                checkEventLog(filename);

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
            ZipFolder(filename);
        }
        else if (lstrcmpi(lpExt, L".evtx") == 0)
        {
            checkEventLog(filename);
        }
    }
}

int wmain(int argc, const wchar_t* argv[])
{
    if (argc <= 1)
    {
        return -1;
    }
    Check(argv[1]);
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
