#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: ISC
#

import os
import sys
import struct
from ramdump import RamDump
from print_out import print_out_str


def read_binary_file(file_path, start_offset=0, count=None):
    stream_low = []
    stream_high = []
    with open(file_path, 'rb') as file:
        file.seek(start_offset)  # Move to the start offset
        index = 0
        while True:
            if count is not None and index >= count:
                break
            bytes_read = file.read(4)
            if len(bytes_read) < 4:
                break
            value = struct.unpack('<I', bytes_read)[0]
            if index % 2 == 0:
                stream_low.append(value)
            else:
                stream_high.append(value)
            index += 1
    return stream_low, stream_high

def extract_gemnoc_poc_dbg_LLCC(file_path, start_offset=0, count=None):
    # Print Stream_low and Stream_high arrays for the first 3 iterations in hexadecimal format
    stream_low, stream_high = read_binary_file(file_path, start_offset, count)

    print_out_str("\n------------GEMNOC LLCC TMO--------------")
    print_out_str(f"Stream_low (first 3 iterations): {[f'0x{val:08x}' for val in stream_low[:3]]}")
    print_out_str(f"Stream_high (first 3 iterations): {[f'0x{val:08x}' for val in stream_high[:3]]}")

    # Calculate Initiator_Type
    initiator_type = (stream_low[0] & 0x100) >> 8
    if initiator_type:
        ext_id = (stream_high[2] >> 9) & 0xFFFF
        bid = (ext_id >> 13) & 0x7
        pid = (ext_id >> 8) & 0x1F
        mid = ext_id & 0xFF
        print_out_str(f"GEMNOC LLCC TMO: ERROR Decode : BID = 0x{bid:x}, PID = 0x{pid:x}, MID = 0x{mid:x}")
    else:
        tgtid = (stream_low[2] & 0xE000000) >> 25
        srcid = (stream_low[2] & 0x70000000) >> 28
        lpid = ((stream_high[2] & 0xE0000000) >> 29) + ((stream_low[3] & 0x3) << 3)
        print_out_str(f"GEMNOC LLCC TMO: ERROR Decode : TGTID = 0x{tgtid:x}, SRCID = 0x{srcid:x}, LPID = 0x{lpid:x}")

    addr_of_violation = ((stream_low[0] + (stream_high[0] << 32)) >> 54) + \
                        ((((stream_low[1] + (stream_high[1] << 32)) & 0x3FFFFFF)) << 10)
    print_out_str(f"GEMNOC LLCC TMO: Address of violation = 0x{addr_of_violation:016x}")

def extract_gemnoc_poc_dbg_PCIE(file_path, start_offset=0, count=None):
    stream_low, stream_high = read_binary_file(file_path, start_offset, count)

    print_out_str("\n------------GEMNOC PCIE TMO--------------")
    # Print Stream_low and Stream_high arrays for the first 3 iterations in hexadecimal format
    print_out_str(f"Stream_low (first 3 iterations): {[f'0x{val:08x}' for val in stream_low[:3]]}")
    print_out_str(f"Stream_high (first 3 iterations): {[f'0x{val:08x}' for val in stream_high[:3]]}")

    # Calculate Initiator_Type
    initiator_type = (stream_low[0] & 0x40) >> 6
    if initiator_type:
        ext_id = ((stream_low[2] & 0x80000000) >> 31) + ((stream_high[2] & 0x7FFF) << 1)
        bid = (ext_id >> 13) & 0x7
        pid = (ext_id >> 8) & 0x1F
        mid = ext_id & 0xFF
        print_out_str(f"GEMNOC QNS PCIE TMO: ERROR Decode : BID = 0x{bid:x}, PID = 0x{pid:x}, MID = 0x{mid:x}")
    else:
        tgtid = (stream_low[2] & 0x38000) >> 15
        srcid = (stream_low[2] & 0x1C0000) >> 18
        lpid = (stream_high[2] & 0xF80000) >> 19
        print_out_str(f"GEMNOC QNS PCIE TMO: ERROR Decode : TGTID = 0x{tgtid:x}, SRCID = 0x{srcid:x}, LPID = 0x{lpid:x}")

    addr_of_violation = ((stream_low[0] + (stream_high[0] << 32)) >> 46) + \
                        ((((stream_low[1] + (stream_high[1] << 32)) & 0x3FFFF)) << 18)
    print_out_str(f"GEMNOC QNS PCIE TMO: Address of violation = 0x{addr_of_violation:016x}")

def extract_gemnoc_poc_dbg_PCNOC(file_path, start_offset=0, count=None):
    stream_low, stream_high = read_binary_file(file_path, start_offset, count)

    print_out_str("\n------------GEMNOC PCNOC TMO--------------")
    # Print Stream_low and Stream_high arrays for the first 3 iterations in hexadecimal format
    print_out_str(f"Stream_low (first 3 iterations): {[f'0x{val:08x}' for val in stream_low[:3]]}")
    print_out_str(f"Stream_high (first 3 iterations): {[f'0x{val:08x}' for val in stream_high[:3]]}")

    # Calculate Initiator_Type
    initiator_type = (stream_low[0] & 0x40) >> 6

    if initiator_type:
        ext_id = (stream_high[2] >> 7) & 0xFFFF
        bid = (ext_id >> 13) & 0x7
        pid = (ext_id >> 8) & 0x1F
        mid = ext_id & 0xFF

        print_out_str(f"GEMNOC QNS PCNOC TMO: ERROR Decode : BID = 0x{bid:x}, PID = 0x{pid:x}, MID = 0x{mid:x}")
    else:
        tgtid = (stream_low[2] & 0x3800000) >> 23
        srcid = (stream_low[2] & 0x1C000000) >> 26
        lpid = (stream_high[2] & 0xF80000000) >> 27

        print_out_str(f"GEMNOC QNS PCNOC TMO: ERROR Decode : TGTID = 0x{tgtid:x}, SRCID = 0x{srcid:x}, LPID = 0x{lpid:x}")

    addr_of_violation = ((stream_low[0] + (stream_high[0] << 32)) >> 52) + \
                        ((((stream_low[1] + (stream_high[1] << 32)) & 0xFFFFFF)) << 12)

    print_out_str(f"GEMNOC QNS PCNOC TMO: Address of violation = 0x{addr_of_violation:016x}")

def get_dcc_dump_addr(ddr_address):
    return (ddr_address & 0xFFFF0000) | 0x09F8
def get_mon_mmu_addr(ddr_address):
    return (ddr_address & 0xFFFF0000) | 0x0A28

# dcc_sram_config structure
dcc_sram_config = {
    5424: {
        "dcc_sram_size": 0x8000,
        "dcc_dump_addr": get_dcc_dump_addr,
        "dumps": [
            {
                "start_offset": 0x554,
                "size_in_bytes": 0x328,
                "function_pointer": extract_gemnoc_poc_dbg_LLCC
            },
            {
                "start_offset": 0x87C,
                "size_in_bytes": 0x328,
                "function_pointer": extract_gemnoc_poc_dbg_PCIE
            },
            {
                "start_offset": 0xBA4,
                "size_in_bytes": 0x328,
                "function_pointer": extract_gemnoc_poc_dbg_PCNOC
            },
        ]
    },
}

def generate_dcc_sram(ramdump, start_offset, num_elements, output_file_path):
    data = ramdump.read_physical(start_offset, num_elements, False)
    with open(output_file_path, 'wb') as output_file:
        output_file.write(data)

def dcc_sram_parser_func(ramdump):

    if ramdump.hw_id is None:
        print("!!!!! No HW ID !!!!!")
        return
    print_out_str(f"Board : ipq-{ramdump.hw_id}")

    if ramdump.hw_id not in dcc_sram_config:
        print_out_str("!!!!! No DCC SRAM CFG for this board !!!!!")
        return

    imem_location = ramdump.tz_addr
    if imem_location == 0:
        print_out_str("Wrong DDR Location: 0x0")
        return
    # print_out_str(f"DDR Location: 0x{imem_location:08X}")

    ddr_address = ramdump.read_word(imem_location, False)
    if ddr_address == 0:
        print_out_str("Wrong DDR Address: 0x0")
        return
    # print_out_str(f"DDR Address: 0x{ddr_address:08X}")

    dump_addr = dcc_sram_config[ramdump.hw_id]["dcc_dump_addr"](ddr_address)
    if dump_addr == 0:
        print_out_str("Wrong Dump Address: 0x0")
        return
    # print_out_str(f" Calculated address: 0x{dump_addr:08X}")

    dcc_sram_struct_info = ramdump.read_u32(dump_addr, virtual=False)
    if dcc_sram_struct_info == 0:
        print_out_str("Wrong DCC SRAM Struct Info: 0x0")
        return
    # print_out_str(f" dcc_sram_struct_info: 0x{dcc_sram_struct_info:08X}")

    SysdbgCPUDumpver = ramdump.read_u32( dcc_sram_struct_info, virtual=False)
    # print_out_str(f"Dump_ver: 0x{SysdbgCPUDumpver:08X}")
    sysdbgmagic = ramdump.read_u32( dcc_sram_struct_info + 4, virtual=False)
    # print_out_str(f"Sysdbgmagic: 0x{sysdbgmagic:08X}")
    if(SysdbgCPUDumpver == 0x14 and sysdbgmagic == 0x42445953):
        print('')
        # print_out_str("\n SysdbgCPUDumpver and sysdbgmagic match")
    else:
        print_out_str("\n !!! SysdbgCPUDumpver and sysdbgmagic does not match !!!")
        return

    dcc_sram_addr = dcc_sram_struct_info + 0x28

    num_elements_address = dcc_sram_addr + 0x8
    num_elements =  ramdump.read_u32( num_elements_address, virtual=False)
    if num_elements == 0:
        print_out_str("Wrong Number of Elements: 0")
        return
    # print_out_str(f"Number of elements: {num_elements}")

    dcc_sram_buf_start_addr = ramdump.read_u32(dcc_sram_addr, virtual=False)
    if dcc_sram_buf_start_addr == 0:
        print_out_str("Wrong DCC SRAM Buffer Start Address: 0x0")
        return
    # print_out_str(f"dcc_sram_buf_start_addr: 0x{dcc_sram_buf_start_addr:08X}")

    output_dir = ramdump.outdir
    output_file_path = os.path.join(output_dir, 'DCC_SRAM.bin')
    generate_dcc_sram(ramdump, dcc_sram_buf_start_addr, num_elements, output_file_path)

    file_path = output_file_path # 'DCC_SRAM.bin'
    for dump in dcc_sram_config[ramdump.hw_id]["dumps"]:
        start_offset = dump["start_offset"]
        count = dump["size_in_bytes"] // 4
        dump["function_pointer"](file_path, start_offset, count)


    # Generate MONITOR.BIN file
    monitor_addr = get_mon_mmu_addr(ddr_address)
    monitor_struct_info=ramdump.read_u32(monitor_addr, virtual=False)
    monitor_start_addr=monitor_struct_info + 0x28
    num_elements_monitor_addr = monitor_start_addr + 0x8
    num_elements_monitor = ramdump.read_u32(num_elements_monitor_addr, virtual=False)
    if num_elements_monitor == 0:
        print_out_str("Wrong Number of Elements for Monitor: 0")
    else:
        monitor_start = ramdump.read_u32(monitor_start_addr, virtual=False)
        if monitor_start == 0:
            print_out_str("Wrong Monitor Start Address: 0x0")
        else:
            output_file_path = os.path.join(output_dir, 'MONITOR.bin')
            generate_dcc_sram(ramdump, monitor_start, num_elements_monitor, output_file_path)
            # print_out_str(f"MONITOR.BIN file generated successfully at {output_file_path}")