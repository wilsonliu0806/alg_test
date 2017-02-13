#ifndef __COMMON_H__
#define __COMMON_H__

#define MAX_EVENT_NUM 10
#ifdef __WIN32
#include <windows.h>
#define sleep(x) Sleep(x)
#else
#include <unistd.h>
#define sleep(x) sleep(x)
#endif

typedef void FUNC(void *);

int event_init();
int event_run();
int event_add(FUNC* func,int when);
#endif