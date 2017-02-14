#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "common.h"
#include "event.h"
struct pri_queue* p = NULL;
int event_init()
{
    p = init_queue(10);
    printf("event init !\n");
    return 0;
}

int event_run()
{
    while(1){
        time_t now = time(NULL);
        struct pri_queue_node *q = get_top_queue(p);
        if(q!= NULL && q->key > now){
            q->func(NULL);
            delete_min(p);
        }
        printf("event run\n");
        sleep(2);
    }
    return 0;
}

int event_add(FUNC* func,int when)
{
    printf("event_add %p when %d\n",func,when);
    time_t now = time(NULL);
    insert_queue(p,func,when+now);
    return 0;
}