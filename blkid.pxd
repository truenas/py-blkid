# encoding: utf-8
# cython: language_level=3, c_string_type=unicode, c_string_encoding=default

from libc cimport stdint

cdef extern from 'blkid.h' nogil:
    cdef struct blkid_struct_cache:
        pass

    cdef struct blkid_struct_dev_iterate:
        pass

    cdef struct blkid_struct_dev:
        # The device object keeps information about one device
        pass

    cdef struct blkid_struct_tag_iterate:
        pass

    cdef struct blkid_struct_probe:
        pass

    cdef struct blkid_struct_partlist:
        # list of all detected partitions and partitions tables
        pass

    cdef struct blkid_struct_parttable:
        # information about a partition table
        pass

    cdef struct blkid_struct_partition:
        # Information about a partition
        pass

    ctypedef blkid_struct_cache * blkid_cache
    ctypedef blkid_struct_dev_iterate * blkid_dev_iterate
    ctypedef blkid_struct_dev * blkid_dev
    ctypedef blkid_struct_tag_iterate * blkid_tag_iterate
    ctypedef blkid_struct_probe * blkid_probe
    ctypedef blkid_struct_partlist * blkid_partlist
    ctypedef blkid_struct_parttable * blkid_parttable
    ctypedef blkid_struct_partition * blkid_partition

    ctypedef stdint.int64_t blkid_loff_t

    # cache.c
    extern int blkid_get_cache(blkid_cache *cache, const char *filename)
    extern void blkid_put_cache(blkid_cache cache);
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
    extern int blkid_probe_enable_superblocks(blkid_probe pr, int enable)
    extern int blkid_probe_set_superblocks_flags(blkid_probe pr, int flags)
    enum:
        BLKID_SUBLKS_LABEL
        BLKID_SUBLKS_UUID
        BLKID_SUBLKS_TYPE
        BLKID_SUBLKS_SECTYPE
        BLKID_SUBLKS_USAGE
        BLKID_SUBLKS_VERSION
    # Partition probing
    extern int blkid_probe_enable_partitions(blkid_probe pr, int enable)
    # NAME=value low-level interface
    extern int blkid_do_fullprobe(blkid_probe pr)
    extern int blkid_probe_numof_values(blkid_probe pr)
    extern int blkid_probe_get_value(blkid_probe pr, int num, const char **name, const char **data, size_t *len)
    extern int blkid_probe_lookup_value(blkid_probe pr, const char *name, const char **data, size_t *len)
    extern int blkid_do_safeprobe(blkid_probe pr)
    # probe.c
    extern blkid_probe blkid_new_probe()
    extern void blkid_free_probe(blkid_probe pr)
    extern int blkid_probe_is_wholedisk(blkid_probe pr)
    extern blkid_loff_t blkid_probe_get_size(blkid_probe pr)
    extern blkid_probe blkid_new_probe_from_filename(const char *filename)
    # Partition probing flags
    extern int blkid_probe_set_partitions_flags(blkid_probe pr, int flags)
    enum:
        BLKID_PARTS_ENTRY_DETAILS
    # devname.c
    extern blkid_dev blkid_get_dev(blkid_cache cache, const char *devname, int flags)
    enum:
        BLKID_DEV_FIND
        BLKID_DEV_CREATE
        BLKID_DEV_VERIFY
        BLKID_DEV_NORMAL
    # Functions to create and find a specific tag type
    extern void blkid_free_dev(blkid_dev dev)
    extern blkid_dev blkid_new_dev()
    # Binary interface
    extern blkid_partlist blkid_probe_get_partitions(blkid_probe pr)
    extern blkid_parttable blkid_partlist_get_table(blkid_partlist ls)
    extern const char *blkid_parttable_get_type(blkid_parttable tab)
    extern blkid_loff_t blkid_parttable_get_offset(blkid_parttable tab)
    extern const char *blkid_parttable_get_id(blkid_parttable tab)
    extern int blkid_partlist_numof_partitions(blkid_partlist ls)
    extern blkid_partition blkid_partlist_get_partition(blkid_partlist ls, int n)
    extern blkid_parttable blkid_partition_get_table(blkid_partition par)
    extern blkid_loff_t blkid_partition_get_start(blkid_partition par)
    extern blkid_loff_t blkid_partition_get_size(blkid_partition par)
    extern int blkid_partition_get_partno(blkid_partition par)
    extern const char *blkid_partition_get_name(blkid_partition par)
    extern const char *blkid_partition_get_uuid(blkid_partition par)
    extern const char *blkid_partition_get_type_string(blkid_partition par)
