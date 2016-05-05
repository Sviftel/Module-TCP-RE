#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include "cache_structure.h"
#include "hashing.h"

#include "hpl_entry.h"

MODULE_LICENSE("GPL");


char module_header[] = "cache_test_module: ";
struct cache *c;


/************/


struct data_entry {
    int cnt;
    struct hpl_entry data;
    struct rb_node t_node;
    struct hlist_node ht_node;
};


void tree_print(struct rb_root *root) {
    struct rb_node *node;
    for (node = rb_first(root); node; node = rb_next(node)) {
        int i;
        struct data_entry *entry;
        entry = container_of(node, struct data_entry, t_node);

        printk("%sPayload: ", module_header);
        for (i = 0; i < entry->data.size; ++i) {
            printk("%c", entry->data.pl[i]);
        }

        printk(" Freq: %d ", entry->cnt);

        printk(" Hash: ");
        for (i = 0; i < 16; ++i) {
            printk("\\x%x", entry->data.hash[i]);
        }
        printk("\n");
    }
}


void cache_ht_print(struct cache *c) {
    struct data_entry *curr_entry;
    int i, k;

    for (k = 0; k < 1 << CACHE_BITS_NUM; ++k) {
        hash_for_each_possible(c->ht, curr_entry, ht_node, k) {

            printk("%sPayload: ", module_header);
            for (i = 0; i < curr_entry->data.size; ++i) {
                printk("%c", curr_entry->data.pl[i]);
            }

            printk(" Freq: %d ", curr_entry->cnt);

            printk(" Hash: ");
            for (i = 0; i < 16; ++i) {
                printk("\\x%x", curr_entry->data.hash[i]);
            }
            printk("\n");
        }
    }
}


/************/


int init_func(void) {
    printk("%sStart working with cache\n", module_header);

    c = kmalloc(sizeof(struct cache), GFP_KERNEL);
    init_cache(c, 256);
    int i, j, entries_num = 3, msg_len = 5;

    alloc_hash_structs();

    unsigned char words[entries_num][msg_len];
    unsigned char ch = 'a';
    for (i = 0; i < entries_num; ++i) {
        for (j = 0; j < msg_len; ++j) {
            words[i][j] = ch + i;
        }

        for (j = 0; j < entries_num - i; ++j) {
            add_to_cache(c, words[i], msg_len);
        }
    }

    printk("%sTest getting payload from cache:\n", module_header);
    for (i = 0; i < entries_num; ++i) {
        printk("%sNext payload: ", module_header);
        unsigned char *pl, h[HASH_LEN];
        int s, _k;

        calc_hash(words[i], msg_len, h);
        get_pl_info(c, h, &pl, &s);

        for (j = 0; j < s; ++j) {
            printk("%c", pl[j]);
        }

        printk(", should be: ");
        for (j = 0; j < msg_len; j++) {
            printk("%c", words[i][j]);
        }
        printk("\n");
    }


    // printk("%sPrint from tree:\n", module_header);
    // tree_print(&(c->tree));

    // printk("%sPrint from hash table:\n", module_header);
    // cache_ht_print(c);

    printk("%sSize, in bytes: %ld, Hitrate: %d\n",
           module_header, c->curr_size, get_hitrate(c));

    return 0;
}


void exit_func(void) {
    clean_cache(c);
    kfree(c);

    free_hash_structs();
    printk("%sStop working with cache\n", module_header);
}


module_init(init_func);
module_exit(exit_func);