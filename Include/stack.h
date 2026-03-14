#ifndef STACK_H
#define STACK_H

#include <stdint.h>

typedef struct stack_node_t {
    uint8_t protocol;           // 当前协议
    void * data;                // 指向协议头的指针
    struct stack_node_t * down; // 下层协议的指针
    struct stack_node_t * up;   // 上层协议的指针
}StackNode;

typedef struct stack_t {
    StackNode * bottom;         // 尾节点
    StackNode * top;            // 头节点
    int size;                   // 协议栈长度
}Stack;

Stack * stack_new(void);
void stack_push(Stack * stack,void * data,uint8_t protocol);
StackNode * stack_pop(Stack * stack);
StackNode * stack_top(const Stack * stack);


#endif