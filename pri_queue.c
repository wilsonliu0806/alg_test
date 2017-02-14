#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pri_queue.h"


void swap_queue_node (struct pri_queue_node *left,struct pri_queue_node *right)
{
    struct pri_queue_node tmp;
    memcpy(&tmp,left,sizeof(tmp));
    memcpy(left,right,sizeof(*left));
    memcpy(right,&tmp,sizeof(*right));
}
struct pri_queue* init_queue(int count)
{
    struct pri_queue *p_q = malloc(sizeof(*p_q));
    p_q->size = 0;
    p_q->q = calloc(count,sizeof(struct pri_queue_node));
    return p_q;
}
int insert_queue(struct pri_queue* pri_q,void *data,int key)
{
    /*
    struct pri_queue_node *pnode = malloc(sizeof(pri_queue_node));
    pnode->data = data;
    pnode->key = key;
    */
    int insert_pos = pri_q->size + 1;//empty postion 
    int parent_pos = insert_pos/2;
    int parent_key = pri_q->q[parent_pos].key;

    while(key<parent_key){
        memcpy(&pri_q->q[insert_pos],&pri_q->q[parent_pos],sizeof(struct pri_queue_node));
        insert_pos = parent_pos;
        parent_pos = parent_pos/2;
        parent_key = pri_q->q[parent_pos].key;
    }
    pri_q->q[insert_pos].func= data;
    pri_q->q[insert_pos].key = key;
    pri_q->size+=1;
}
void * delete_min(struct pri_queue *p){
    void *data = p->q[1].func;
    int hole_index = 1;
    int empty_index = p->size;
    int left_index = 2*hole_index <empty_index?2*hole_index:empty_index;
    int right_index = 2*hole_index+1<empty_index?2*hole_index+1:empty_index;
    struct pri_queue_node *hole = &p->q[hole_index];
    struct pri_queue_node *left = &p->q[left_index];
    struct pri_queue_node *right= &p->q[right_index];
    struct pri_queue_node *min = left->key < right->key?left:right;
    struct pri_queue_node *insert = &p->q[empty_index];
    printf("delete min key = %d\n",hole->key);
    printf("insert key = %d\n",insert->key);
    printf("min key = %d\n",min->key);
    while(insert->key > min->key){
        memcpy(hole,min,sizeof(*hole));
        hole = min;
        hole_index = (min - p->q);
        printf("hole_index %d\n",hole_index);
        left_index = 2*hole_index <empty_index?2*hole_index:empty_index;
        printf("left_index %d\n",left_index);
        right_index = 2*hole_index+1<empty_index?2*hole_index+1:empty_index;
        printf("right_index %d\n",right_index);
        left = &p->q[left_index];
        right= &p->q[right_index];
        min = left->key <right->key?left:right; 
    }

    memcpy(hole,insert,sizeof(*hole));
    p->size--;

}
void dump_queue(struct pri_queue *p)
{
    int i = 1;
    for(;i<=p->size;i++){
        printf("%p %d\n",p->q[i].func,p->q[i].key);
    }
}

struct pri_queue_node* get_top_queue(struct pri_queue *p)
{
    if(p->size>0){
        return &p->q[1];
    }else{
        return NULL;
    }
}