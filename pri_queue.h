#ifndef __PRI_QUEUE_H_
#define __PRI_QUEUE_H_
#define DEFAULT_QUEUE_SIZE 100
typedef void FUNC(void *);
struct pri_queue_node{
    FUNC*   func;
    int     key;
};
struct pri_queue{
    struct pri_queue_node *q;
    int     size;
};

struct pri_queue* init_queue(int count);
int insert_queue(struct pri_queue* pri_q,void *data,int key);
void dump_queue(struct pri_queue *p);
void * delete_min(struct pri_queue *p);
struct pri_queue_node* get_top_queue(struct pri_queue *p);
#endif