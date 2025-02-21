// SPDX-License-Identifier: MIT

#include "pidset.h"
#include <stddef.h>
#include <malloc.h>

bool pidset_create(struct pidset* set, int capacity)
{
    set->size = 0;
    set->capacity = capacity;
    set->buffer = calloc(capacity, sizeof(s_pidlist));

    if (set->buffer == NULL) {
        set->capacity = 0;
        return false;
    }

    return true;
}

void pidset_destroy(struct pidset* set)
{
    // Make sure to free all the linked lists
    // before freeing the array
    for (int i = 0; i < set->size; i++) {
        // 0th element is stored in-place, so free() should
        // be called only for the next elements
        s_pidlist* list = set->buffer[i].next;

        while (list != NULL) {
            s_pidlist* next = list->next;
            free(list);
            list = next;
        }
    }
    free(set->buffer);
    set->size = 0;
}

static bool pidset_extend_if_needed(struct pidset* set)
{
    int capacity_threshold_percent = 75;

    if (set->size * 100 <= set->capacity * capacity_threshold_percent) {
        return true;
    }

    int old_capacity = set->capacity;

    set->capacity *= 2;
    s_pidlist* new_buffer = calloc(set->capacity, sizeof(s_pidlist));

    if (new_buffer == NULL) {
        return false;
    }

    s_pidlist* old_buffer = set->buffer;
    set->buffer = new_buffer;
    set->size = 0;

    // Add all the elements from the old buffer to the new buffer
    for (int i = 0; i < old_capacity; i++) {
        pidset_add(set, old_buffer[i].pid);
        s_pidlist* list = old_buffer[i].next;

        while (list != NULL) {
            pidset_add(set, list->pid);
            s_pidlist* next = list->next;
            pidset_add(set, list->pid);
            free(list);
            list = next;
        }
    }

    free(old_buffer);

    return true;
}

bool pidset_add(struct pidset* set, pid_t pid)
{
    if (!pidset_extend_if_needed(set)) {
        return false;
    }

    int index = pid % set->capacity;

    // Since first element is stored in-place, it's necessary
    // to check it separately
    if (set->buffer[index].pid == 0) {
        set->buffer[index].pid = pid;
        set->size++;
        return true;
    }

    s_pidlist* list = set->buffer[index].next;

    while (list != NULL) {
        if (list->pid == pid) {
            return true;
        }
        list = list->next;
    }

    list = malloc(sizeof(s_pidlist));
    list->pid = pid;
    list->next = set->buffer[index].next;
    set->buffer[index].next = list;
    set->size++;
    return true;
}

void pidset_remove(struct pidset* set, pid_t pid)
{
    int index = pid % set->capacity;

    s_pidlist* list = &set->buffer[index];

    // First list element is handled separately, since it's stored in-place
    if (list->pid == pid) {
        set->size--;

        // Move the next element to the buffer and free the next element

        s_pidlist* next = set->buffer[index].next;
        if (next == NULL) {
            list->pid = 0;
            return;
        }

        list->pid = next->pid;
        list->next = next->next;
        free(next);
        return;
    }

    while (list != NULL) {
        s_pidlist* next = list->next;
        if (next != NULL && next->pid == pid) {
            set->size--;
            list->next = next->next;
            free(next);
            return;
        }
        list = next;
    }
}

bool pidset_contains(struct pidset* set, pid_t pid)
{
    int index = pid % set->capacity;

    s_pidlist* list = &set->buffer[index];

    while (list != NULL) {
        if (list->pid == pid) {
            return true;
        }
        list = list->next;
    }

    return false;
}
