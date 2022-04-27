#ifndef REMOTE_DBG_H
#define REMOTE_DBG_H

#include <winsock2.h>
#include <Windows.h>

#pragma comment(lib,"ws2_32.lib") //Winsock Library

void RemoteDBG_Init();
void RemoteDBG_Release();

#endif //REMOTE_DBG_H