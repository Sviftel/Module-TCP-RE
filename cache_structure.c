#include "cache_structure.h"
#include <linux/slab.h>

// 251 = 2^8 - 5
#define MULTIPL 251
// 65521 = 2^16 - 2^8 + 7
#define MOD 65287


// TODO: add timestamp fields
struct data_entry {
    int cnt;
    struct hpl_entry data;
    struct rb_node t_node;
    struct hlist_node ht_node;
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


int __tree_insert(struct rb_root *root, struct data_entry *entry) {
    struct rb_node **new = &(root->rb_node), *parent = NULL;

    while (*new) {
        struct data_entry *curr_entry;
        curr_entry = container_of(*new, struct data_entry, t_node);

        parent = *new;
        if (entry->cnt <= curr_entry->cnt)
            new = &((*new)->rb_left);
        else
            new = &((*new)->rb_right);
    }

    rb_link_node(&(entry->t_node), parent, new);
    rb_insert_color(&(entry->t_node), root);

    return 1;
}


void __tree_remove(struct rb_root *tree, struct data_entry *entry) {
    rb_erase(&(entry->t_node), tree);
}


// function also frees entry, should be
// called after __ht_clean()
void __tree_rec_clean(struct rb_node *node) {
    if (node == NULL)
        return;

    __tree_rec_clean(node->rb_left);
    __tree_rec_clean(node->rb_right);
    node->rb_left = NULL;
    node->rb_right = NULL;

    struct data_entry *entry;
    entry = container_of(node, struct data_entry, t_node);
    free_hpl_entry(&(entry->data));
    kfree(entry);
    node = NULL;
}


void __ht_clean(struct cache *c) {
    int k;

    for (k = 0; k < 1 << CACHE_BITS_NUM; ++k) {
        c->ht[k].first = NULL;
    }
}


void __remove_entry_from_cache(struct cache *c) {
    struct rb_node *node_to_rm = rb_first(&(c->tree));
    struct data_entry *entry_to_rm;
    entry_to_rm = container_of(node_to_rm, struct data_entry, t_node);

    __tree_remove(&(c->tree), entry_to_rm);
    hash_del(&(entry_to_rm->ht_node));
    c->curr_size -= entry_to_rm->data.size;

    free_hpl_entry(&(entry_to_rm->data));
    kfree(entry_to_rm);
}


// TODO: add lists to solve collisions
unsigned char *add_to_cache(struct cache *c, unsigned char *pl, int s) {
    struct hpl_entry new_hpl_entry;
    unsigned int k;

    new_hpl_entry.pl = pl;
    new_hpl_entry.size = s;
    __get_hash_key_to_buff(pl, s, new_hpl_entry.hash, &k);

    struct data_entry *curr_entry;

    hash_for_each_possible(c->ht, curr_entry, ht_node, k) {
        if (eq_hpl_entries(&(curr_entry->data), &new_hpl_entry))
        {
            curr_entry->cnt += 1;
            __tree_remove(&(c->tree), curr_entry);
            __tree_insert(&(c->tree), curr_entry);
            c->hits++;
            c->saved_traffic_size += s;
            c->total_traffic_size += s;
            return curr_entry->data.hash;
        }
    }

    while (c->curr_size + s > c->max_size) {
        __remove_entry_from_cache(c);
    }

    struct data_entry *new_entry;
    new_entry = kmalloc(sizeof(struct data_entry), GFP_KERNEL);

    new_entry->cnt = 1;
    fill_hpl_entry(&(new_entry->data), pl, s);

    __tree_insert(&(c->tree), new_entry);
    INIT_HLIST_NODE(&(new_entry->ht_node));
    hash_add(c->ht, &(new_entry->ht_node), k);

    c->curr_size += s;
    c->misses++;
    c->total_traffic_size += s;

    return NULL;
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
    __ht_clean(c);
    __tree_rec_clean(c->tree.rb_node);
    c->tree.rb_node = NULL;
    c->curr_size = 0;
}


void get_pl_info(struct cache *c, unsigned char *hash_val,
                 unsigned char **pl, int *pl_s)
{
    int k = __get_key_from_hash(hash_val);

    struct data_entry *curr_entry;
    hash_for_each_possible(c->ht, curr_entry, ht_node, k) {
        if (eq_hash_vals(hash_val, curr_entry->data.hash))
        {
            curr_entry->cnt += 1;
            __tree_remove(&(c->tree), curr_entry);
            __tree_insert(&(c->tree), curr_entry);
            c->hits++;
            c->saved_traffic_size += curr_entry->data.size;

            *pl = curr_entry->data.pl;
            *pl_s = curr_entry->data.size;
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
