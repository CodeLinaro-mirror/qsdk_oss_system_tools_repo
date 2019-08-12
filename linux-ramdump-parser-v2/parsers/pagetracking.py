# Copyright (c) 2012,2014 The Linux Foundation. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and
# only version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

import os
import collections
from print_out import print_out_str
from parser_util import register_parser, RamParser
from mm import pfn_to_page, mm_page_ext

symbols = {}

nss_modules = [ "qca_nss_dp", "qca_nss_drv", "qca_nss_qdisc" , "qca_nss_crypto",
                "qca_nss_cfi_ocf" ]
wifi_modules = [ "qdf", "wifi_3_0", "qca_ol", "umac", "cfg80211",
                 "qca_spectral" ]

def gen_symbol_info(nm_path="nm", elf="vmlinux"):
    symbolfile = elf + ".syms"
    if os.path.exists(symbolfile) == False:
        os.system(nm_path + " --defined-only -l " + elf + " > " + symbolfile)

    if os.path.exists(symbolfile):
        fd = open(symbolfile, "r")
        data = fd.readlines()
        for symbolline in data:
            info = (symbolline.split(" "))[2].split("\t")
            if len(info) == 2 and info[0].find("$") == -1:
                symbols[info[0]] = info[1].strip()

def filename_from_vmlinux(function):
    if function.strip() == "":
        return ""

    if symbols.has_key(function):
        return symbols[function]

    return ""

def order_to_size(order):
    if order < 0:
       return 0
    return (1 << order) * 4096

class meminfo_ranked:
    def __init__(self, ramdump):
        self.ramdump = ramdump
        self.meminfos = {}

    def __str__(self):
        s = ""
        for addr_str in self.meminfos:
            s += str(self.meminfos[addr_str])

        return s

    def insert(self, pfns, addrs, size, flags):
        addr_str = ""
        for addr in addrs:
            addr_str += str(hex(addr)) + " "
        if self.meminfos.has_key(addr_str):
            self.meminfos[addr_str].update_meminfo(pfns, addrs, size, flags)
        else:
            mi = meminfo(self.ramdump, pfns, addrs, size, flags)
            self.meminfos[addr_str] = mi

    def sort_by_size(self):
        meminfo_sorted = collections.OrderedDict(
                           sorted(self.meminfos.items(),
                                  key = lambda page : page[1].total_size,
                                  reverse=True))
        return meminfo_sorted

class meminfo:
    def __init__(self, ramdump, pfns, addrs, size, flags):
        self.ramdump = ramdump
        if self.ramdump.arm64:
            self.ULONG_MAX = 0xffffffffffffffff
        else:
            self.ULONG_MAX = 0xffffffff
        self.pfns = []
        self.size = []
        self.total_size = 0
        self.functions = []
        self.modules = []
        self.stack_str = ""
        self.allocation_type = ""
        self.category = ""
        self.subcategory = ""

        self.addrs = addrs
        self.flags = flags

        for addr in addrs:
            try:
                stackinfo = self.ramdump.unwind_lookup(addr)
                function, offset, module, fnsize = stackinfo
            except ValueError:
                function = 'UNKNOWN'
                fnsize = 0
                module = None
                offset = 0
            except TypeError:
                function = 'UNKNOWN'
                fnsize = 0
                module = None
                offset = 0

            self.stack_str += symbol_info_str(addr, function, offset, fnsize,
                                              module) + "\n"
            self.functions.append(function)
            if module != None:
                self.modules.append(module)
        self.update_meminfo(pfns, addrs, size, flags)

        self.classify()

    def obj_in_str(self, include_pfns=False):
        uniq_size_str = []
        uniq_size = set(self.size)
        for us in uniq_size:
            uniq_size_str.append("{0}*{1}".format(self.size.count(us), us))

        s = "Size: " + str(uniq_size_str) + "\n"
        s += "Total Size: " + str(self.total_size) + "\n"
        s += "Allocation Type: " + self.allocation_type + "\n"
        s += "Flags: " + self.flags + "\n"
        s += "Category: " + self.category + "\n"
        s += "Subcategory: " + self.subcategory + "\n"
        s += "Modules: " + str(self.modules) + "\n"
        if include_pfns:
            s += "PFNs: " + str(self.pfns) + "\n"
        s += self.stack_str
        s += "\n"
        return s

    def __str__(self):
        return self.obj_in_str(False)

    def update_meminfo(self, pfns, addrs, size, flags):
        for pfn in pfns:
            self.pfns.append(pfn)
        self.size.append(size)
        self.total_size += size

    def classify(self):
        if self.is_kernel_private():
            self.allocation_type = "Fallback"
        else:
            self.find_alloc_type()
            self.find_is_network_stack()

    def is_kernel_private(self):
        if len(self.addrs) == 1 and self.addrs[0] == self.ULONG_MAX:
            return True
        elif self.stack_str.find("page_ext_init") >= 0:
            return True
        return False

    def find_is_network_stack(self):
        for mod in self.modules:
            for nwmod in nss_modules:
                if mod == nwmod:
                    self.category = "Networking"
                    self.subcategory = "NSS"
                    return

        for mod in self.modules:
            for nwmod in wifi_modules:
                if mod == nwmod:
                    self.category = "Networking"
                    self.subcategory = "WiFi"
                    return

        for function in self.functions:
            filename = filename_from_vmlinux(function)
            if filename.find("net") >= 0:
                self.category = "Networking"
                self.subcategory = "Kernel"
                return

    def find_alloc_type(self):
        if self.flags.find("S") >= 0:
            self.allocation_type = "SLUB Allocation"
            return

        if self.flags.find("L") >= 0:
            self.allocation_type = "Page Cache"
            return

        s = self.stack_str
        if self.flags == "":
            if s.find("pte_alloc_kernel") >= 0:
                self.allocation_type = "IO Remapped Allocation"
            elif s.find("dma_alloc") >= 0:
                self.allocation_type = "DMA Allocation"
            elif s.find("vmalloc") >= 0:
                self.allocation_type = "VMalloc Allocation"
            else:
                self.allocation_type = "Alloc Pages allocation"
        elif (s.find("do_page_fault") >= 0) or (s.find("handle_mm_fault") >= 0):
            self.allocation_type = "User Space Allocation"

        return

def symbol_info_str(addr, function, offset, size, module):
    if size == 0:
        return " [<{0}>] {1}".format(hex(addr)[2:], hex(addr))
    elif module == None:
        return " [<{0}>] {1}+{2}/{3}".format(hex(addr)[2:], function, hex(offset), hex(size))
    else:
        return " [<{0}>] {1}+{2}/{3} [{4}]".format(hex(addr)[2:], function, hex(offset), hex(size), module)

@register_parser('--print-pagetracking', 'print page tracking information (if available)')
class PageTracking(RamParser):
    def __init__(self, ramdump):
        self.ramdump = ramdump
        self.pageflags = {}

    def get_flags_str(self, flags):
        flags_str = ""
        for i in self.pageflags:
            if flags & (1 << i):
                flags_str += self.pageflags[i]

        return flags_str

    def parse(self):
        ramdump = self.ramdump

        if not ramdump.is_config_defined('CONFIG_PAGE_OWNER'):
            return

        cmdline = ramdump.get_command_line()
        if cmdline.find("page_owner=on") == -1:
            return

        pageflags_table = ramdump.gdbmi.get_enum_lookup_table(
            'pageflags', 26)
        self.pageflags[pageflags_table.index("PG_slab")] = 'S'
        self.pageflags[pageflags_table.index("PG_lru")] = 'L'

        page_ext_flags_table = ramdump.gdbmi.get_enum_lookup_table(
            'page_ext_flags', 5)
        PAGE_EXT_OWNER = (1 << page_ext_flags_table.index('PAGE_EXT_OWNER'))

        page_ext_obj = mm_page_ext(ramdump)

        gen_symbol_info(ramdump.nm_path, ramdump.vmlinux)

        min_pfn = page_ext_obj.get_min_pfn()
        max_pfn = page_ext_obj.get_max_pfn()

        page_flags_offset = ramdump.field_offset('struct page', 'flags')
        order_offset = ramdump.field_offset('struct page_ext', 'order')
        page_ext_flags_offset = ramdump.field_offset('struct page_ext', 'flags')
        nr_entries_offset = ramdump.field_offset(
            'struct page_ext', 'nr_entries')
        trace_entries_offset = ramdump.field_offset(
            'struct page_ext', 'trace_entries')
        trace_entry_size = ramdump.sizeof("void *")

        out_tracking = ramdump.open_file('page_tracking.txt')
        out_tracking_all = ramdump.open_file('page_tracking_all.txt')
        page_info = meminfo_ranked(self.ramdump)

        pfn = min_pfn
        while pfn < max_pfn:
            order = 0
            trace_entries = []
            page_ext = page_ext_obj.lookup_page_ext(pfn)
            page_ext_flags = ramdump.read_word(page_ext + page_ext_flags_offset)

            if ((page_ext_flags & PAGE_EXT_OWNER) == PAGE_EXT_OWNER):
                page = pfn_to_page(ramdump, pfn)
                page_flags = ramdump.read_u32(page + page_flags_offset)

                order = ramdump.read_u32(page_ext + order_offset)
                nr_trace_entries = ramdump.read_int(page_ext + nr_entries_offset)

                flags = self.get_flags_str(page_flags)
                size = order_to_size(order)

                for i in range(0, nr_trace_entries):
                    entry = ramdump.read_word(
                        page_ext + trace_entries_offset + i * trace_entry_size)
                    trace_entries.append(entry)
                page_info.insert(range(pfn, pfn + (1 << order)), trace_entries, size, flags)

            pfn += (1 << order)

        alloc_size = 0

        dma_size = 0
        network_dma_size = 0
        wifi_dma_size = 0
        nss_dma_size = 0

        direct_page_alloc_size = 0
        network_direct_page_alloc_size = 0
        wifi_direct_page_alloc_size = 0
        nss_direct_page_alloc_size = 0

        slub_alloc_size = 0
        other_alloc_size = 0

        kernel_used_size = 0

        sorted_meminfo = page_info.sort_by_size()
        for info in sorted_meminfo:
            m = sorted_meminfo[info]
            out_tracking_all.write(m.obj_in_str(True))

            if m.allocation_type == "Fallback":
                kernel_used_size += m.total_size
                continue

            if m.allocation_type == "IO Remapped Allocation":
                alloc_size += m.total_size
                continue

            alloc_size += m.total_size

            if m.flags == "" and m.allocation_type == "DMA Allocation":
                dma_size += m.total_size
                if m.category == "Networking":
                    if m.subcategory == "WiFi":
                        wifi_dma_size += m.total_size
                    if m.subcategory == "NSS":
                        nss_dma_size += m.total_size
            elif m.allocation_type == "Alloc Pages allocation":
                direct_page_alloc_size += m.total_size
                if m.category == "Networking":
                    if m.subcategory == "WiFi":
                        wifi_direct_page_alloc_size += m.total_size
                    if m.subcategory == "NSS":
                        nss_direct_page_alloc_size += m.total_size

            if m.flags.find("S") >= 0:
                slub_alloc_size += m.total_size

            out_tracking.write(str(m))

        network_dma_size = wifi_dma_size + nss_dma_size
        network_direct_page_alloc_size = (wifi_direct_page_alloc_size +
                                          nss_direct_page_alloc_size)
        other_alloc_size = alloc_size - (dma_size + direct_page_alloc_size +
                                         slub_alloc_size)

        out_tracking_all.close()
        out_tracking.close()

        print_out_str("Total pages allocated: {0} KB".format(alloc_size / 1024))

        print_out_str("\tTotal DMA allocation: {0} KB".format(dma_size / 1024))
        print_out_str("\t\tNetwork DMA allocation: {0} KB".format(network_dma_size/ 1024))
        print_out_str("\t\t\tWiFi DMA allocation: {0} KB".format(wifi_dma_size / 1024))
        print_out_str("\t\t\tNSS DMA allocation: {0} KB".format(nss_dma_size / 1024))

        print_out_str("\tDirect page allocation: {0} KB".format(direct_page_alloc_size / 1024))
        print_out_str("\t\tNetwork direct page allocation: {0} KB".format(network_direct_page_alloc_size / 1024))
        print_out_str("\t\t\tWiFi direct page allocation: {0} KB".format(wifi_direct_page_alloc_size / 1024))
        print_out_str("\t\t\tNSS direct page allocation: {0} KB".format(nss_direct_page_alloc_size / 1024))

        print_out_str("\tTotal SLUB allocation: {0} KB".format(slub_alloc_size / 1024))
        print_out_str("\tOther allocation: {0} KB".format(other_alloc_size / 1024))

        print_out_str("Kernel private: {0} KB\n".format(kernel_used_size / 1024))

        print_out_str(
            '---wrote page tracking information to page_tracking.txt')
