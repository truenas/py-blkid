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


class DeviceNotFound(BlkidException):
    def __init__(self, device):
        super().__init__(errno.ENOENT, f'Device {device} not found')


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
                    block_devices.append(BlockDevice(devname.decode()))

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


cdef class BlkidProbe:
    cdef blkid.blkid_probe pr
    cdef const char * name

    def __cinit__(self, devname):
        if not os.path.exists(devname):
            raise DeviceNotFound(devname)
        encoded = devname.encode()
        self.name = encoded

    def __enter__(self):
        with nogil:
            self.pr = blkid.blkid_new_probe_from_filename(self.name)
        if self.pr == NULL:
            raise BlkidException(-1, f'Failed to create libblkid probe for {self.name.decode()}')
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        with nogil:
            blkid.blkid_free_probe(self.pr)
        self.pr = NULL

    cdef object retrieve_values(self):
        if self.pr == NULL:
            raise BlkidException(errno.ENXIO, 'No libblkid probe defined')

        probing_data = {}
        cdef const char * name, * data
        cdef int nvals
        with nogil:
            nvals = blkid.blkid_probe_numof_values(self.pr)
            for i in range(nvals):
                if blkid.blkid_probe_get_value(self.pr, i, &name, &data, NULL) != 0:
                    continue
                with gil:
                    probing_data[name.decode()] = data.decode()

        return probing_data


cdef class BlockDevice:
    cdef str device_name

    def __cinit__(self, str name, int flags=0, Cache cache=None):
        self.device_name = name

        if not self.device_name:
            raise BlkidException(errno.EINVAL, 'Please specify either device object or block device name')
        elif not os.path.exists(self.device_name):
            raise BlkidException(errno.EINVAL, f'{self.device_name} does not exist')
        elif not stat.S_ISBLK(os.stat(self.name).st_mode):
            raise BlkidException(errno.EINVAL, 'Please specify a valid block device')

    def __getstate__(self, superblock_mode=True, partition_data_filters=None):
        return {
            'name': self.name,
            'partitions_exist': self.partitions_exist,
            'superblock_exist': self.superblock_exist,
            **self.lowprobe_device(superblock_mode=superblock_mode),
            **self.retrieve_partition_data(partition_data_filters),
        }

    property name:
        def __get__(self):
            return self.device_name

    property superblock_exist:
        def __get__(self):
            return 'TYPE' in self.lowprobe_device(superblock_mode=True)

    def partition_data(self, filters=None):
        return self.retrieve_partition_data(filters)

    cdef object retrieve_partition_data(self, filter_values=None):
        partition_data = {}
        if not self.has_partitions():
            # There is no partition related data
            return partition_data

        cdef BlkidProbe probe = BlkidProbe(self.name)
        cdef blkid.blkid_partlist ls
        cdef blkid.blkid_parttable root_tab
        cdef blkid.blkid_loff_t device_size, offset, start, part_size
        cdef const char * partition_type, * partition_id, * part_name, * part_uuid
        cdef int no_of_partitions, part_no
        cdef blkid.blkid_partition par
        cdef blkid.blkid_parttable tab

        partitions = []

        with probe:
            with nogil:
                ls = blkid.blkid_probe_get_partitions(probe.pr)
                if ls == NULL:
                    raise BlkidException(-1, f'Failed to read partitions for {self.name} device')
                root_tab = blkid.blkid_partlist_get_table(ls)
                if root_tab == NULL:
                    raise BlkidException(-1, f'{self.name} device does not contain any known partition table')

                device_size = blkid.blkid_probe_get_size(probe.pr)
                partition_type = blkid.blkid_parttable_get_type(root_tab)
                offset = blkid.blkid_parttable_get_offset(root_tab)
                partition_id = blkid.blkid_parttable_get_id(root_tab)
                no_of_partitions = blkid.blkid_partlist_numof_partitions(ls)
                for i in range(no_of_partitions):
                    par = blkid.blkid_partlist_get_partition(ls, i)
                    tab = blkid.blkid_partition_get_table(par)
                    # Retrieve partition data
                    part_no = blkid.blkid_partition_get_partno(par)
                    start = blkid.blkid_partition_get_start(par)
                    part_size = blkid.blkid_partition_get_size(par)
                    part_name = blkid.blkid_partition_get_name(par)
                    part_uuid = blkid.blkid_partition_get_uuid(par)
                    with gil:
                        partitions.append({
                            'partition_number': part_no,
                            'partition_start': start,
                            'partition_size': part_size,
                            'part_name': part_name.decode() if part_name != NULL else None,
                            'part_uuid': part_uuid.decode() if part_uuid != NULL else None,
                        })

            if filter_values is None or 'partitions' in filter_values:
                partition_data['partitions'] = partitions
                partition_data['no_of_partitions'] = no_of_partitions
            if filter_values is None or 'device_size' in filter_values:
                partition_data['device_size'] = device_size
            if filter_values is None or 'partition_offset' in filter_values:
                partition_data['partition_offset'] = offset

            partition_data['partition_id'] = partition_id.decode()

        return partition_data

    cdef has_partitions(self):
        cdef BlkidProbe probe = BlkidProbe(self.name)
        cdef int ret
        with probe:
            with nogil:
                blkid.blkid_probe_enable_partitions(probe.pr, 1)
                blkid.blkid_do_fullprobe(probe.pr)

                ret = blkid.blkid_probe_lookup_value(probe.pr, 'PTTYPE', NULL, NULL)
        return ret == 0

    cdef lowprobe_device(self, superblock_mode=False):
        cdef int ret, file_no, enable_superblock, nvals = 0, s_block_mode = superblock_mode
        cdef const char * name, * data
        cdef BlkidProbe probe = BlkidProbe(self.name)

        with probe:
            with nogil:
                if s_block_mode:
                    blkid.blkid_probe_set_superblocks_flags(
                        probe.pr, blkid.BLKID_SUBLKS_LABEL | blkid.BLKID_SUBLKS_UUID | blkid.BLKID_SUBLKS_TYPE
                            | blkid.BLKID_SUBLKS_SECTYPE | blkid.BLKID_SUBLKS_USAGE | blkid.BLKID_SUBLKS_VERSION
                    )

                blkid.blkid_probe_enable_topology(probe.pr, 1)
                blkid.blkid_probe_enable_superblocks(probe.pr, 0)
                blkid.blkid_probe_enable_partitions(probe.pr, 0)
                ret = blkid.blkid_do_fullprobe(probe.pr)
                if ret < 0:
                    raise BlkidException(-1, 'Failed to probe device')
                if ret or s_block_mode:
                    blkid.blkid_probe_enable_partitions(probe.pr, 1)
                    blkid.blkid_probe_set_partitions_flags(probe.pr, blkid.BLKID_PARTS_ENTRY_DETAILS)
                    blkid.blkid_probe_enable_superblocks(probe.pr, 1)
                    if blkid.blkid_do_safeprobe(probe.pr) < 0:
                        raise BlkidException(-1, 'Failed to probe device')

            probing_data = probe.retrieve_values()

        return probing_data

    def probing_data(self, superblock_mode=False):
        return self.lowprobe_device(superblock_mode)

    property partitions_exist:
        def __get__(self):
            return self.has_partitions()


def list_block_devices(clean_cache=False, cache_filename=None):
    return list(Cache(clean_cache, cache_filename))


def list_supported_filesystems():
    return Cache().supported_filesystems()
