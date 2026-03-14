#include "stack.h"
#include "protc.h"
#include "hdr.h"

// Created by cs_ca on 2026/3/14.
//

Stack * stack_new(void) {
    Stack * stack = malloc(sizeof(Stack));
    if (stack == NULL) return NULL;
    stack->top = stack->bottom =  NULL;
    stack->size = 0;
    return stack;
}


void stack_push(Stack * stack,void * data,uint8_t protocol) {
    StackNode * node = malloc(sizeof(StackNode));
    if (node == NULL) return;
    node->data = data;
    node->protocol = protocol;
    node->up = node->down = NULL;
    // 如果没有底层协议，说明是空bottom就为当前协议
    if (stack->bottom == NULL) {
        stack->bottom = node;
    }
    // 如果top不为空，那top的up是新的协议
    //当前协议的down是top
    if (stack->top != NULL) {
        stack->top->up = node;
        node->down = stack->top;
    }
    stack->top = node;
    stack->size++;
}

StackNode * stack_pop(Stack * stack) {
    if (stack->top == NULL || stack->size == 0) return  NULL;
    StackNode * node = stack->top;
    if (stack->top == stack->bottom) {
        stack->bottom = NULL;
    }

    stack->top = stack->top->down;
    stack->top->up = NULL;
    stack->size--;
    return node;
}
StackNode * stack_top(const Stack * stack) {
    if (stack->top == NULL || stack->size == 0) return NULL;
    return stack->top;
}