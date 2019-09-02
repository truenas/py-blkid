# encoding: utf-8
# cython: language_level=3, c_string_type=unicode, c_string_encoding=default

from libc cimport stdint

cdef extern from 'blkid.h' nogil:
    cdef struct blkid_struct_cache:
        pass

    cdef struct blkid_struct_dev_iterate:
        pass

    ctypedef struct blkid_struct_dev:
        # The device object keeps information about one device
        pass

    ctypedef struct blkid_struct_tag_iterate:
        pass

    ctypedef struct blkid_struct_probe:
        pass

    ctypedef blkid_struct_cache * blkid_cache
    ctypedef blkid_struct_dev_iterate * blkid_dev_iterate
    ctypedef blkid_struct_dev * blkid_dev
    ctypedef blkid_struct_tag_iterate * blkid_tag_iterate
    ctypedef blkid_struct_probe * blkid_probe

    ctypedef stdint.int64_t blkid_loff_t

    extern int blkid_get_cache(blkid_cache *cache, const char *filename)
    extern void blkid_gc_cache(blkid_cache cache)
    extern int blkid_probe_all(blkid_cache cache)
    extern blkid_dev_iterate blkid_dev_iterate_begin(blkid_cache cache)
    extern int blkid_dev_set_search(blkid_dev_iterate iter, const char *search_type, const char *search_value)
    extern int blkid_dev_next(blkid_dev_iterate iterate, blkid_dev *dev)
    extern blkid_dev blkid_verify(blkid_cache cache, blkid_dev dev)
    extern const char *blkid_dev_devname(blkid_dev dev)
    extern void blkid_dev_iterate_end(blkid_dev_iterate iterate)
    extern blkid_tag_iterate blkid_tag_iterate_begin(blkid_dev dev)
    extern int blkid_tag_next(blkid_tag_iterate iterate, const char **type, const char **value)
    extern void blkid_tag_iterate_end(blkid_tag_iterate iterate)
    extern int blkid_probe_set_device(blkid_probe pr, int fd, blkid_loff_t off, blkid_loff_t size)
    extern char *blkid_evaluate_tag(const char *token, const char *value, blkid_cache *cache)
    # topology probing
    extern int blkid_probe_enable_topology(blkid_probe pr, int enable)
    # Superblock probing
    extern int blkid_probe_enable_superblocks(blkid_probe pr, int enable)
    extern int blkid_superblocks_get_name(size_t idx, const char **name, int *usage)
    # Partition probing
    extern int blkid_probe_enable_partitions(blkid_probe pr, int enable)
    # NAME=value low-level interface
    extern int blkid_do_fullprobe(blkid_probe pr)
    extern int blkid_probe_numof_values(blkid_probe pr)
    extern int blkid_probe_get_value(blkid_probe pr, int num, const char **name, const char **data, size_t *len)
    # probe.c
    extern blkid_probe blkid_new_probe()
    extern void blkid_free_probe(blkid_probe pr)
