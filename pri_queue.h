#ifndef __PRI_QUEUE_H_
#define __PRI_QUEUE_H_
#define DEFAULT_QUEUE_SIZE 100
struct pri_queue_node{
    void*   data;
    int     key;
};
struct pri_queue{
    struct pri_queue_node *q;
    int     size;
};

struct pri_queue* init_queue(int count,int elt_size);
int insert_queue(struct pri_queue* pri_q,void *data,int key);
void dump_queue(struct pri_queue *p);
void * delete_min(struct pri_queue *p);
#endif