#ifndef __COMMON_H__
#define __COMMON_H__

#define MAX_EVENT_NUM 10
#ifdef __WIN32
#include <windows.h>
#define sleep(x) Sleep(x*1000)
#else
#include <unistd.h>
#define sleep(x) sleep(x)
#endif


#endif