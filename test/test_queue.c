#include <stdio.h>
#include "../pri_queue.h"

int main()
{
    printf("--test pri_queue!\n");
    int input[]={1,6,7,3,2};
    struct pri_queue *p = init_queue(10,sizeof(int));
    int i = 0;
    for(;i<sizeof(input)/sizeof(int);i++){
        printf("--insert %d\n",input[i]);
        insert_queue(p,&input[i],input[i]);
        dump_queue(p);
    }

    for(i=0;i<sizeof(input)/sizeof(int);i++){
        delete_min(p);
        dump_queue(p);
    }
    return 0;
}