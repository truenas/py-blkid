cimport blkid

import errno
import os
import stat


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
    cdef const char * cache_filename

    def __cinit__(self, renew_cache=False, cache_filename=None):
        if renew_cache:
            cache_filename = '/dev/null'

        if cache_filename:
            encoded_filename = cache_filename.encode()
            self.cache_filename = encoded_filename
        else:
            self.cache_filename = NULL

        with nogil:
            ret = blkid.blkid_get_cache(&self.cache, self.cache_filename)
            if ret != 0:
                raise BlkidCacheException(ret, 'Unable to retrieve cache')


    def __dealloc__(self):
        blkid.blkid_put_cache(self.cache)

    cdef get_devices(self, char *search_type, char *search_value):
        cdef blkid.blkid_dev_iterate blkid_iter
        cdef blkid.blkid_dev dev
        cdef char *devname
        block_devices = []

        with nogil:
            ret = blkid.blkid_probe_all(self.cache)
            if ret != 0:
                raise BlkidException(ret, 'Failed to probe devices')

            blkid_iter = blkid.blkid_dev_iterate_begin(self.cache)

            blkid.blkid_dev_set_search(blkid_iter, search_type, search_value)

            while blkid.blkid_dev_next(blkid_iter, &dev) == 0:
                dev = blkid.blkid_verify(self.cache, dev)
                if dev == NULL:
                    continue
                devname = blkid.blkid_dev_devname(dev)
                with gil:
                    block_devices.append(BlockDevice(devname.decode(), blkid.BLKID_DEV_FIND, self))

            blkid.blkid_dev_iterate_end(blkid_iter)

        return block_devices

    cdef void _garbage_collect_cache(self) nogil:
        blkid.blkid_gc_cache(self.cache)

    def garbage_collect_cache(self):
        self._garbage_collect_cache()

    cpdef supported_filesystems(self):
        cdef const char * name
        cdef size_t idx = 0
        supported_fs = []

        with nogil:
            while blkid.blkid_superblocks_get_name(idx, &name, NULL) == 0:
                with gil:
                    idx += 1
                    supported_fs.append(name.decode())

        return supported_fs

    def __iter__(self):
        return iter(self.get_devices(NULL, NULL))


cdef class BlockDevice:
    cdef blkid.blkid_dev dev
    cdef Cache cache
    cdef str device_name

    def __cinit__(self, str name, int flags=0, Cache cache=None):
        self.device_name = name

        if not self.device_name:
            raise BlkidException(errno.EINVAL, 'Please specify either device object or block device name')
        elif not os.path.exists(self.device_name):
            raise BlkidException(errno.EINVAL, f'{self.device_name} does not exist')

        self.cache = cache or Cache()
        cache_obj = self.cache.cache
        cdef blkid.blkid_cache cache_p = <blkid.blkid_cache>cache_obj

        flags = flags or blkid.BLKID_DEV_FIND

        encoded_device_name = self.device_name.encode()
        cdef const char * dev_name = encoded_device_name
        with nogil:
            self.dev = blkid.blkid_get_dev(cache_p, dev_name, flags)

    def __getstate__(self, superblock_mode=False):
        return {
            'name': self.name,
            **self.tags,
            **self.lowprobe_device(superblock_mode=superblock_mode),
        }

    property name:
        def __get__(self):
            return self.device_name

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

    cdef lowprobe_device(self, superblock_mode=False):
        cdef int ret, file_no, character_device, enable_superblock, nvals = 0, s_block_mode = superblock_mode
        cdef const char * name, * data
        cdef blkid.blkid_probe pr = blkid.blkid_new_probe()
        if pr == NULL:
            raise BlkidException(-1, 'Unable to allocate probing struct')

        probing_data = {}

        with open(os.open(self.name, os.O_RDONLY|os.O_CLOEXEC), 'r') as f:
            file_no = f.fileno()
            character_device = stat.S_ISCHR(os.stat(self.name).st_mode)
            with nogil:
                if blkid.blkid_probe_set_device(pr, file_no, 0, 0) != 0:
                    raise BlkidException(-1, 'Unable to assign the device to probe control structure')
                if s_block_mode:
                    blkid.blkid_probe_set_superblocks_flags(
                        pr, blkid.BLKID_SUBLKS_LABEL | blkid.BLKID_SUBLKS_UUID | blkid.BLKID_SUBLKS_TYPE
                            | blkid.BLKID_SUBLKS_SECTYPE | blkid.BLKID_SUBLKS_USAGE | blkid.BLKID_SUBLKS_VERSION
                    )

                blkid.blkid_probe_enable_topology(pr, 1)
                blkid.blkid_probe_enable_superblocks(pr, 0)
                blkid.blkid_probe_enable_partitions(pr, 0)
                ret = blkid.blkid_do_fullprobe(pr)
                if ret < 0:
                    raise BlkidException(-1, 'Failed to probe device')
                if ret or s_block_mode:
                    blkid.blkid_probe_enable_partitions(pr, 1)
                    enable_superblock = 1
                    if character_device and blkid.blkid_probe_get_size(pr) <= (1024 * 1440) and \
                            blkid.blkid_probe_is_wholedisk(pr):
                        # TODO: Please verify why 1024 * 1440 ?
                        blkid.blkid_probe_enable_superblocks(pr, 0)
                        ret = blkid.blkid_do_fullprobe(pr)
                        if ret < 0:
                            raise BlkidException(-1, 'Failed to probe device')
                        enable_superblock = blkid.blkid_probe_lookup_value(pr, 'PTTYPE', NULL, NULL)

                    if enable_superblock != 0:
                        blkid.blkid_probe_set_partitions_flags(pr, blkid.BLKID_PARTS_ENTRY_DETAILS)
                        blkid.blkid_probe_enable_superblocks(pr, 1)
                        if blkid.blkid_do_safeprobe(pr) < 0:
                            raise BlkidException(-1, 'Failed to probe device')

                nvals = blkid.blkid_probe_numof_values(pr)
                for i in range(nvals):
                    if blkid.blkid_probe_get_value(pr, i, &name, &data, NULL) != 0:
                        continue
                    with gil:
                        probing_data[name.decode()] = data.decode()

        blkid.blkid_free_probe(pr)

        return probing_data

    property probing_data:
        def __get__(self):
            return self.lowprobe_device()


def list_block_devices(clean_cache=False, cache_filename=None):
    return list(Cache(clean_cache, cache_filename))


def list_supported_filesystems():
    return Cache().supported_filesystems()
