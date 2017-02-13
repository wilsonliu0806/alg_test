#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "common.h"
#include "pri_queue.h"

int event_init()
{
    printf("event init !\n");
    return 0;
}

int event_run()
{
    while(1){
        printf("event run\n");
        sleep(1000);
    }
    return 0;
}

int event_add(FUNC* func,int when)
{
    func(NULL);
    printf("event_add %p when %d\n",func,when);
    return 0;
}