#include <stdio.h>
#include "../common.h"
#include "../event.h"
void Useage()
{
    printf("Useage:simple algrithom tester!\n");
    return ;
}

int main()
{
    event_init();
    event_add(Useage,1);
    event_run();
    return 0;
}