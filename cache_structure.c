#include "cache_structure.h"
#include <linux/slab.h>

// 251 = 2^8 - 5
#define MULTIPL 251
// 65521 = 2^16 - 2^8 + 7
#define MOD 65287


// TODO: add fields to join structures
// TODO: add timestamp fields
struct rbtree_entry {
    int cnt;
    struct hpl_entry data;
    struct rb_node node;
};


struct ht_entry {
    struct rbtree_entry *rb_entry;
    struct hlist_node node;
};


unsigned int __get_key_from_hash(unsigned char *hash) {
    unsigned int i, key;
    key = 0;
    for (i = 0; i < HASH_LEN; i += 2) {
        unsigned int addit = hash[i];

        // key = (O(2**16) + O(2**8) * O(2**8)) % O(2**16)
        key = (key + addit * MULTIPL) % MOD;
    }

    return key;
}


void __get_hash_key_to_buff(unsigned char *pl, int s,
                        unsigned char *hash, unsigned int *key)
{
    calc_hash(pl, s, hash);
    *key = __get_key_from_hash(hash);
}


int __tree_insert(struct rb_root *root, struct rbtree_entry *entry) {
    struct rb_node **new = &(root->rb_node), *parent = NULL;

    while (*new) {
        struct rbtree_entry *curr_entry;
        curr_entry = container_of(*new, struct rbtree_entry, node);

        parent = *new;
        if (entry->cnt <= curr_entry->cnt)
            new = &((*new)->rb_left);
        else
            new = &((*new)->rb_right);
    }

    rb_link_node(&(entry->node), parent, new);
    rb_insert_color(&(entry->node), root);

    return 1;
}


void __tree_remove(struct rb_root *tree, struct rbtree_entry *rb_entry) {
    rb_erase(&(rb_entry->node), tree);
}


void __tree_rec_clean(struct rb_node *node) {
    if (node == NULL)
        return;

    __tree_rec_clean(node->rb_left);
    __tree_rec_clean(node->rb_right);
    node->rb_left = NULL;
    node->rb_right = NULL;

    struct rbtree_entry *entry;
    entry = container_of(node, struct rbtree_entry, node);
    free_hpl_entry(&(entry->data));
    kfree(entry);
    node = NULL;
}


void __remove_entry_from_cache(struct cache *c) {
    struct rb_node *node_to_rm = rb_first(&(c->tree));
    struct rbtree_entry *rb_entry_to_rm;
    rb_entry_to_rm = container_of(node_to_rm, struct rbtree_entry, node);

    int k = __get_key_from_hash(rb_entry_to_rm->data.hash);
    struct ht_entry *curr_ht_entry;
    struct rbtree_entry *curr_rb_entry;
    hash_for_each_possible(c->ht, curr_ht_entry, node, k) {
        curr_rb_entry = curr_ht_entry->rb_entry;

        if (eq_hpl_entries(&(curr_rb_entry->data), &(rb_entry_to_rm->data)))
        {
            __tree_remove(&(c->tree), rb_entry_to_rm);
            hash_del(&(curr_ht_entry->node));
            c->curr_size -= rb_entry_to_rm->data.size;

            free_hpl_entry(&(rb_entry_to_rm->data));
            kfree(rb_entry_to_rm);
            kfree(curr_ht_entry);
            return;
        }
    }
}

// TODO: add lists to solve collisions
unsigned char *add_to_cache(struct cache *c, unsigned char *pl, int s) {
    struct hpl_entry new_hpl_entry;
    unsigned int k;

    new_hpl_entry.pl = pl;
    new_hpl_entry.size = s;
    __get_hash_key_to_buff(pl, s, new_hpl_entry.hash, &k);

    struct ht_entry *curr_ht_entry;
    struct rbtree_entry *curr_rb_entry;

    hash_for_each_possible(c->ht, curr_ht_entry, node, k) {
        curr_rb_entry = curr_ht_entry->rb_entry;

        if (curr_rb_entry != NULL &&
            eq_hpl_entries(&(curr_rb_entry->data), &new_hpl_entry))
        {
            curr_rb_entry->cnt += 1;
            __tree_remove(&(c->tree), curr_rb_entry);
            __tree_insert(&(c->tree), curr_rb_entry);
            c->hits++;
            c->saved_traffic_size += s;
            c->total_traffic_size += s;
            return curr_rb_entry->data.hash;
        }
    }

    while (c->curr_size + s > c->max_size) {
        __remove_entry_from_cache(c);
    }

    struct rbtree_entry *new_rb_entry;
    new_rb_entry = kmalloc(sizeof(struct rbtree_entry), GFP_KERNEL);

    new_rb_entry->cnt = 1;
    fill_hpl_entry(&(new_rb_entry->data), pl, s);
    __tree_insert(&(c->tree), new_rb_entry);

    struct ht_entry *new_ht_entry;
    new_ht_entry = kmalloc(sizeof(struct ht_entry), GFP_KERNEL);
    new_ht_entry->rb_entry = new_rb_entry;
    INIT_HLIST_NODE(&(new_ht_entry->node));
    // TODO: think about &(c->ht[0]) to do similar with &(c->tree)
    hash_add(c->ht, &(new_ht_entry->node), k);

    c->curr_size += s;
    c->misses++;
    c->total_traffic_size += s;

    return NULL;
}


void __ht_clean(struct cache *c) {
    int k;
    struct ht_entry *curr_ht_entry;
    struct hlist_node *curr_node;

    for (k = 0; k < 1 << CACHE_BITS_NUM; ++k) {
        curr_node = c->ht[k].first;

        while (curr_node != NULL) {
            curr_ht_entry = container_of(curr_node, struct ht_entry, node);
            curr_node = curr_node->next;
            kfree(curr_ht_entry);
        }

        c->ht[k].first = NULL;
    }
}


void init_cache(struct cache *c, int cache_size) {
    c->max_size = cache_size * 1024 * 1024;
    c->curr_size = 0;
    c->hits = 0;
    c->misses = 0;
    c->saved_traffic_size = 0;
    c->total_traffic_size = 0;

    c->tree = RB_ROOT;
    hash_init(c->ht);
}


void clean_cache(struct cache *c) {
    __tree_rec_clean(c->tree.rb_node);
    c->tree.rb_node = NULL;
    __ht_clean(c);
    c->curr_size = 0;
}


void get_pl_info(struct cache *c, unsigned char *hash_val,
                 unsigned char **pl, int *pl_s)
{
    int k = __get_key_from_hash(hash_val);

    struct ht_entry *curr_ht_entry;
    struct rbtree_entry *curr_rb_entry;
    hash_for_each_possible(c->ht, curr_ht_entry, node, k) {
        curr_rb_entry = curr_ht_entry->rb_entry;

        if (eq_hash_vals(hash_val, curr_rb_entry->data.hash))
        {
            curr_rb_entry->cnt += 1;
            __tree_remove(&(c->tree), curr_rb_entry);
            __tree_insert(&(c->tree), curr_rb_entry);
            c->hits++;
            c->saved_traffic_size += curr_rb_entry->data.size;

            *pl = curr_rb_entry->data.pl;
            *pl_s = curr_rb_entry->data.size;
            return;
        }
    }
    pl = NULL;
    *pl_s = 0;
}



int get_hitrate(struct cache *c) {
    if (c->misses == 0)
        return 0;

    return 100 * c->hits / (c->hits + c->misses);
}

int get_saved_traffic_part(struct cache *c) {
    if (c->total_traffic_size == 0)
        return 0;

    return 100 * c->saved_traffic_size / c->total_traffic_size;
}
