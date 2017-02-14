#include "common.h"
#include "pri_queue.h"

int event_init();
int event_run();
int event_add(FUNC* func,int when);