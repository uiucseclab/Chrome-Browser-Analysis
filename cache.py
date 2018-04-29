import sys
from struct import unpack
from os import path
import os
from datetime import datetime, timedelta
import re
import copy
import gzip


class Block():
    INDEX_MAGIC = 0xC103CAC3
    BLOCK_MAGIC = 0xc104cac3
    INDEX = 0
    BLOCK = 1

    def __init__(self, filename):
        with open(filename, 'rb') as header:
            m = unpack('I', header.read(4))[0]
            if m == Block.BLOCK_MAGIC:
                header.seek(2, 1)
                self.block_type = Block.BLOCK
                self.version = unpack('h', header.read(2))[0]
                self.this_file = unpack('h', header.read(2))[0]  # Index of this file
                self.next_file = unpack('h', header.read(2))[0]  # Next file when this one is full
                self.entry_size = unpack('I', header.read(4))[0]  # Size of the blocks of this file.
                self.num_entries = unpack('I', header.read(4))[0]  # Number of stored entries.
                self.max_entries = unpack('I', header.read(4))[0]  # Current maximum number of entries.
                self.empty = [unpack('I', header.read(4))[0] for _ in range(4)]  # Counters of empty entries for each type.
                self.hints = [unpack('I', header.read(4))[0] for _ in range(4)]  # Last used position for each entry type.
            elif m == Block.INDEX_MAGIC:
                header.seek(2, 1)
                self.block_type = Block.INDEX
                self.version = unpack('h', header.read(2))[0]
                self.num_entries = unpack('I', header.read(4))[0]  # Number of entries currently stored.
                self.num_bytes = unpack('I', header.read(4))[0]  # Total size of the stored data.
                self.last_file = 'f_{:06x}'.format(unpack('I', header.read(4))[0])  # Last external file created.
                header.seek(8, 1)
                self.table_len = unpack('I', header.read(4))[0]  # Actual size of the table (0 == kIndexTablesize)
            else:
                raise Exception("Not a valid index")

class Address():
    SEPARATE_FILE = 0
    RANKING_BLOCK = 1
    BLOCK_256 = 2
    BLOCK_1024 = 3
    BLOCK_4096 = 4

    # Separate file, ranking file, 256 block file, 1k block file, 4k block file
    type_sizes = [0, 36, 256, 1024, 4096]

    def __init__(self, addr, path):
        if addr == 0:
            raise Exception("Null pointer")


        self.addr = addr
        self.path = path

        self.block_type = int(bin(addr)[3:6], 2)

        if self.block_type == Address.SEPARATE_FILE:
            self.file_name = 'f_{:06x}'.format(int(bin(addr)[6:], 2))
        elif self.block_type == Address.RANKING_BLOCK:
            self.file_name = 'data_' + str(int(bin(addr)[10:18], 2))
        else:
            self.entry_size = Address.type_sizes[self.block_type]
            self.contiguous_block = int(bin(addr)[8:10], 2)
            self.file_name = 'data_' + str(int(bin(addr)[10:18], 2))
            self.block_num = int(bin(addr)[18:], 2)


class Entry():
    def __init__(self, address):
        with open(path.join(address.path, address.file_name), 'rb') as block:
            block.seek(8192 + address.block_num * address.entry_size)

            self.hash = unpack('I', block.read(4))[0]  # Full hash of the key.
            self.next = unpack('I', block.read(4))[0]  # Next entry with the same hash or bucket.
            self.rankings_node = unpack('I', block.read(4))[0]
            self.reuse_count = unpack('I', block.read(4))[0]
            self.refetch_count = unpack('I', block.read(4))[0]
            self.state = unpack('I', block.read(4))[0]
            self.creationTime = datetime(1601, 1, 1) + timedelta(microseconds=unpack('Q', block.read(8))[0])
            self.key_len = unpack('I', block.read(4))[0]
            self.long_key = unpack('I', block.read(4))[0]
            self.data_size = [unpack('I', block.read(4))[0] for _ in range(4)]
            self.data = []
            for i in range(4):
                a = unpack('I', block.read(4))[0]
                try:
                    addr = Address(a, address.path)
                    self.data.append(Data(addr, self.data_size[i], True))
                    # if self.data[i].type == Data.HTTP_HEADER:
                    #     self.httpHeader = self.data[i]
                except:
                    pass

            self.httpHeader = None
            for data in self.data:
                if data.data_type == Data.HTTP_HEADER:
                    self.httpHeader = data
                    break

            self.flags = unpack('I', block.read(4))[0]

            block.seek(5*4, 1)

            if self.long_key == 0:
                self.key = block.read(self.key_len).decode('ascii')
            else:
                self.key = Data(Address(self.long_key, address.path), self.key_len, True)

class Data():
    HTTP_HEADER = 0
    OTHER = 1
    def __init__(self, address, size, ishttpheader=False):
        self.size = size
        self.address = address
        self.data_type = Data.OTHER


        with open(path.join(self.address.path, self.address.file_name), 'rb') as data:
            if self.address.block_type == Address.SEPARATE_FILE:
                self.data = data.read()
            else:
                data.seek(8192 + self.address.block_num * self.address.entry_size)
                self.data = data.read(size)

        if ishttpheader and self.address.block_type != Address.SEPARATE_FILE:
            data_copy = copy.deepcopy(self.data)
            start = re.search(b'HTTP', data_copy)
            if start is None:
                return
            else:
                data_copy = data_copy[start.start():]

            end = re.search(b'\x00\x00', data_copy)
            if end is None:
                return
            else:
                data_copy = data_copy[:end.end() - 2]

            self.data_type = Data.HTTP_HEADER
            self.headers = {}
            for line in data_copy.split(b'\x00')[1:]:
                strip = line.split(b':')
                v = b':'.join(strip[1:])
                v = v.decode(encoding='utf-8')
                k = strip[0].decode(encoding='utf-8').lower()
                self.headers[k] = v

if __name__ == '__main__':
    chrome_dir = sys.argv[1]

    cache_path = path.join(chrome_dir, 'Application Cache', 'Cache')
    index_path = path.join(cache_path, 'index')
    cacheBlock = Block(index_path)

    if cacheBlock.block_type != Block.INDEX:
        raise Exception("Not a valid index")

    with open(index_path, 'rb') as index:
        index.seek(92*4)
        cache = []
        for key in range(cacheBlock.table_len):
            raw = unpack('I', index.read(4))[0]
            if raw != 0:
                entry = Entry(Address(raw, cache_path))
                cache.append(entry)
                while entry.next != 0:
                    entry = Entry(Address(entry.next, cache_path))
                    cache.append(entry)

    for entry in cache:
        for i, d in enumerate(entry.data):
            if d is not entry.httpHeader:
                t = 'unknown'
                if entry.httpHeader is not None:
                    t = entry.httpHeader.headers['content-type'].split(';')[0].strip()

                name = hex(entry.hash) + '_' + str(i)
                data_path = path.join('out', t, name)
                os.makedirs(path.dirname(data_path), exist_ok=True)
                with open(data_path, 'wb') as data_f:
                    data_f.write(d.data)

                if entry.httpHeader.headers.get('content-encoding') == 'gzip':
                    try:
                        unzipped = None
                        with gzip.open(data_path) as g:
                            unzipped = g.read()
                        with open(data_path, 'wb') as data_f:
                            data_f.write(unzipped)
                    except IOError:
                        pass
        if entry.httpHeader is not None:
            name = hex(entry.hash) + '.header'
            t = entry.httpHeader.headers['content-type'].split(';')[0].strip()
            header_path = path.join('out', t, name)
            os.makedirs(path.dirname(header_path), exist_ok=True)
            with open(header_path, 'w') as header_f:
                for key, value in entry.httpHeader.headers.items():
                    header_f.write("{}: {}\n".format(key, value))

