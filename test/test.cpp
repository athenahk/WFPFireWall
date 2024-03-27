// test.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include<Windows.h>
#include<fwpmu.h>
#include<locale>
#include<codecvt>
#include<guiddef.h>
#include<initguid.h>
#include <iostream>
DEFINE_GUID(FIREWALL_ENGINE_SUBLAYER_KEY,
    0xb1f8e8ce, 0xd562, 0x4a51, 0x88, 0xb8, 0x3e, 0x1c, 0x23, 0xe2, 0xd2, 0xf9);
using namespace std;
int enumSubLayer(HANDLE handle)
{
    HANDLE engineHandle = NULL;
    DWORD result = ERROR_SUCCESS;
    FWPM_SESSION0 fwpmSession;
    memset(&fwpmSession, 0, sizeof(FWPM_SESSION0));
    fwpmSession.flags = FWPM_SESSION_FLAG_DYNAMIC;

    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &fwpmSession,
        &engineHandle);
    if (result != ERROR_SUCCESS)
    {
        printf("[%s]FwpmEngineOpen0 failed;Return value:%d.\n", __FUNCTION__,
            result);
        return 0;
    }

    HANDLE enumHandle = NULL;
    result = FwpmSubLayerCreateEnumHandle0(engineHandle, NULL, &enumHandle);
    if (result != ERROR_SUCCESS)
    {
        printf("[%s]FwpmSubLayerCreateEnumHandle, Return value:%d\n", __FUNCTION__,
            result);
        FwpmEngineClose0(engineHandle);
        return 0;
    }

    UINT32 numEntriesReturned = 0;
    do
    {
        FWPM_SUBLAYER0** fwpmSubLayerList = NULL;
        numEntriesReturned = 0;
        result = FwpmSubLayerEnum0(engineHandle, enumHandle, 1, &fwpmSubLayerList,
            &numEntriesReturned);
        if (result != ERROR_SUCCESS || numEntriesReturned == 0)
        {
            break;
        }
        std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
        std::string subLayerName = converter.to_bytes(fwpmSubLayerList[0]->displayData.name);
        printf("[%s]subLayer name:%s\n", __FUNCTION__, subLayerName.c_str());
        FwpmFreeMemory0((void**)&fwpmSubLayerList);
    } while (numEntriesReturned > 0);

    result = FwpmSubLayerDestroyEnumHandle0(engineHandle, enumHandle);
    if (result != ERROR_SUCCESS)
    {
        printf("[%s]FwpmSubLayerDestroyEnumHandle, Return value:%d\n",
            __FUNCTION__, result);
        FwpmEngineClose0(engineHandle);
        return 0;
    }

    result = FwpmEngineClose0(engineHandle);
    if (result != ERROR_SUCCESS)
    {
        printf("[%s]FwpmEngineClose0 failed; Return value:%d\n", __FUNCTION__,
            result);
        return 0;
    }
    printf("[%s]result Success\n", __FUNCTION__);
}
int main()
{
    std::cout << "Hello World!\n";

    HANDLE engineHandle = NULL;
    DWORD result = ERROR_SUCCESS;
    FWPM_SESSION0 fwpmSession;
    memset(&fwpmSession, 0, sizeof(FWPM_SESSION0));
    fwpmSession.flags = FWPM_SESSION_FLAG_DYNAMIC;

    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &fwpmSession,
        &engineHandle);
    if (result != ERROR_SUCCESS)
    {
        printf("[%s]FwpmEngineOpen0 failed;Return value:%d.\n", __FUNCTION__,
            result);
        return 0;
    }

  
    if (result != ERROR_SUCCESS)
    {
        printf("[%s]FwpmSubLayerAdd0, Return value:%d\n", __FUNCTION__, result);
        FwpmEngineClose0(engineHandle);
        return 0;
    }
    printf("after add\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\n");

        enumSubLayer(engineHandle);

    FwpmSubLayerDeleteByKey0(engineHandle, (const GUID*)&FIREWALL_ENGINE_SUBLAYER_KEY);
    printf("after del\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\n");

        enumSubLayer(engineHandle);
    result = FwpmEngineClose0(engineHandle);
    if (result != ERROR_SUCCESS)
    {
        printf("[%s]FwpmEngineClose0 failed; Return value:%d\n", __FUNCTION__,
            result);
        return 0;
    }

    printf("[%s]result Success\n", __FUNCTION__);
    system("pause");
    return 0;
}


// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
