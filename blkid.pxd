# encoding: utf-8
# cython: language_level=3, c_string_type=unicode, c_string_encoding=default

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

    ctypedef blkid_struct_cache * blkid_cache
    ctypedef blkid_struct_dev_iterate * blkid_dev_iterate
    ctypedef blkid_struct_dev * blkid_dev
    ctypedef blkid_struct_tag_iterate * blkid_tag_iterate

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
    extern char *blkid_evaluate_tag(const char *token, const char *value, blkid_cache *cache)
