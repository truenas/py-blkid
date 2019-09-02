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
        names = []

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
                    names.append(devname.decode())

            blkid.blkid_dev_iterate_end(blkid_iter)

        return names

    def __iter__(self):
        return iter(self.get_devices(NULL, NULL))


def list_block_devices():
    return list(Cache())
