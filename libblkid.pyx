cimport blkid

class BlkidException(Exception):
    def __init__(self, code, message):
        super(Exception, self).__init__(message)
        self.code = code

    def __reduce__(self):
        return self.__class__, (self.code, self.args)


class BlkidCacheException(BlkidException):
    pass


cdef class Cache:
    cdef blkid.blkid_cache cache

    def __cinit__(self):
        with nogil:
            ret = blkid.blkid_get_cache(&self.cache, NULL)
            if ret != 0:
                raise BlkidCacheException(ret, 'Unable to retrieve cache')

    cdef get_devices(self, char *search_type, char *search_value):
        cdef blkid.blkid_dev_iterate blkid_iter
        cdef blkid.blkid_dev dev
        cdef char *devname
        block_devices = []

        with nogil:
            blkid_iter = blkid.blkid_dev_iterate_begin(self.cache)
            ret = blkid.blkid_probe_all(self.cache)
            if ret != 0:
                raise BlkidException(ret, 'Failed to probe devices')

            blkid.blkid_dev_set_search(blkid_iter, search_type, search_value)

            while blkid.blkid_dev_next(blkid_iter, &dev) == 0:
                dev = blkid.blkid_verify(self.cache, dev)
                if dev == NULL:
                    continue
                devname = blkid.blkid_dev_devname(dev)
                with gil:
                    block_devices.append(BlockDevice(<object>dev))

            blkid.blkid_dev_iterate_end(blkid_iter)

        return block_devices

    cdef void _garbage_collect_cache(self) nogil:
        blkid.blkid_gc_cache(self.cache)

    def garbage_collect_cache(self):
        self._garbage_collect_cache()

    def __iter__(self):
        return iter(self.get_devices(NULL, NULL))


cdef class BlockDevice(object):
    cdef blkid.blkid_dev dev

    def __cinit__(self, object device):
        # TODO: Let's make sure user is not able to instantiate this
        self.dev = <blkid.blkid_dev>device

    def __getstate__(self):
        return {
            'name': self.name,
            **self.tags
        }

    property name:
        def __get__(self):
            return (blkid.blkid_dev_devname(self.dev)).decode()

    property tags:
        def __get__(self):
            cdef blkid.blkid_tag_iterate tag_iterator = blkid.blkid_tag_iterate_begin(self.dev)
            cdef char *tag_type, *value
            cdef int ret = 0
            tags = {}
            while True:
                with nogil:
                    ret = blkid.blkid_tag_next(tag_iterator, &tag_type, &value)
                if ret != 0:
                    with nogil:
                        blkid.blkid_tag_iterate_end(tag_iterator)
                    break

                tags[tag_type.decode()] = value.decode()

            return tags

def list_block_devices():
    return list(Cache())
