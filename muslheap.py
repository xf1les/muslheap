#!/usr/bin/env python
from __future__ import print_function
import gdb
import os
import re

VERSION = "1.1"

# http://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/malloc.c?h=v1.2.2#n12
SIZE_CLASSES = [
    1, 2, 3, 4, 5, 6, 7, 8,
    9, 10, 12, 15,
    18, 20, 25, 31,
    36, 42, 50, 63,
    72, 84, 102, 127,
    146, 170, 204, 255,
    292, 340, 409, 511,
    584, 682, 818, 1023,
    1169, 1364, 1637, 2047,
    2340, 2730, 3276, 4095,
    4680, 5460, 6552, 8191,
]

# http://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/meta.h?h=v1.2.2#n14
UNIT = 16
IB   = 4

# http://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/malloc.c?h=v1.2.2#n40
# `ctx` (or `__malloc_context`) contains mallocng internal status (such as `active` and `free_meta_head`)
CTX = None # May be modified by check_mallocng()

# Coloring functions
RED_BOLD   = lambda x : "\033[1;31m" + str(x) + "\033[m"
GREEN_BOLD = lambda x : "\033[1;32m" + str(x) + "\033[m"
YLW_BOLD   = lambda x : "\033[1;33m" + str(x) + "\033[m"
BLUE_BOLD  = lambda x : "\033[1;34m" + str(x) + "\033[m"
MGNT_BOLD  = lambda x : "\033[1;35m" + str(x) + "\033[m"
CYAN_BOLD  = lambda x : "\033[1;36m" + str(x) + "\033[m"
WHT_BOLD   = lambda x : "\033[1;37m" + str(x) + "\033[m"

YLW  = lambda x : "\033[0;33m" + str(x) + "\033[m"
BLUE = lambda x : "\033[0;34m" + str(x) + "\033[m"
MGNT = lambda x : "\033[0;35m" + str(x) + "\033[m"
WHT  = lambda x : "\033[0;37m" + str(x) + "\033[m"

UINT32_MASK = (1 << 32) - 1
UINT64_MASK = (1 << 64) - 1

MAGIC_VARIABLES = [
    "__malloc_context->secret", "__malloc_replaced", 
    "__stderr_used", "__stdin_used", "__stdout_used", "ofl_head", 
    "__environ", "__stack_chk_guard"
]
MAGIC_FUNCTIONS = [
    "system", "execve", "fexecve", 
    "open", "read", "write", 
    "syscall"
]

def get_ptr_at(addr, type):
    '''Create a gdb.Value object at given address, then cast it to the pointer of specified datatype
    
    Equals to this c statement: 
        return (type*)(addr)
    
    See https://sourceware.org/gdb/onlinedocs/gdb/Values-From-Inferior.html for more information about gdb.Value
    '''
    v = gdb.Value(addr)
    t = gdb.lookup_type(type).pointer()
    return v.cast(t)
    
def get_ptr_value_at(addr, type):
    ''' Get value from given address, then convert it to specified datatype
    
    Equals to this c statement: 
        return *(type*)(addr)
    '''
    return get_ptr_at(addr, type).dereference()

def get_symbol_value(name):
    ''' Get gdb.Value object for given symbol '''
    sym, _ = gdb.lookup_symbol(name)
    if sym != None:
        return sym.value()
    else:
        return None

def check_mallocng():
    ''' Check if mallocng is availble on current environment
    
    It simply checks if `__malloc_context` symbol is existed. If so, set the symbol vaule found as `CTX`.
    '''
    global CTX

    sv = get_symbol_value('__malloc_context')
    if sv == None:
        err_msg = """\
ERROR: can't find musl-libc debug symbols!

muslheap.py requires musl-libc 1.2.1+ with debug symbols installed. 

Either debug symbols are not installed or broken, or a libc without mallocng support (e.g. musl-libc < 1.2.1 or glibc) is used."""
        print(err_msg)
        return False
    else:
        CTX = sv
    return True

def parse_vmmap():
    ''' Parse memory mappings of currently running process.

        It returns a list of tuples like `(start, end, size, offset, objfile)`.
    '''

    result = []
    lines = gdb.execute("info proc mappings", False, True).split('\n')
    if not lines or len(lines) < 4:
        print(RED_BOLD("Warning: can't get memory mappings!\n"))
    else:
        for line in lines[4:]:
            mapping = re.findall(r"(0x\S+)\s+(0x\S+)\s+(0x\S+)\s+(0x\S+)\s+(.*)", line)
            if mapping and mapping[0] and len(mapping[0]) == 5: # Skip mapping without objfile
                start, end, size, offset, objfile = mapping[0]
                # Convert to integer type
                start, end, size, offset = map(lambda x : int(x, 16), [start, end, size, offset])
                objfile = objfile.strip()
                result.append((start, end, size, offset, objfile))
    return result

def get_libcbase():
    ''' Find and get libc.so base address from current memory mappings '''
    
    # XXX: any other alternative names for the musl-libc library?
    soname_pattern = [
        r"^ld-musl-.+\.so\.1$",
        r"^libc\.so$",
        r"^libc\.musl-.+\.so\.1$",
    ]

    vmmap = parse_vmmap()
    for mapping in vmmap:
        objfile = mapping[4]
        if not objfile or objfile.startswith('['):
            continue
        objfn = os.path.basename(objfile)
        for pattern in soname_pattern:
            if re.match(pattern, objfn):
                start = mapping[0]
                return start

    print(RED_BOLD("Warning: can't find musl-libc in memory mappings!\n"))

    # Return None if we can't get libcbase
    return None

def generate_mask_str(avail_mask, freed_mask):
    ''' Generate pretty-print string for avail_mask and freed_mask

        Example:
           avail_mask : 0x7f80 (0b111111110000000)
           freed_mask : 0x0    (0b000000000000000)
    '''

    # Hex strings for avail_mask and freed_mask
    ah = _hex(avail_mask)
    fh = _hex(freed_mask)
    maxlen = max(len(ah), len(fh))
    ah = ah.ljust(maxlen)   # fills ' '
    fh = fh.ljust(maxlen)

    # Binary strings for avail_mask and freed_mask
    ab = _bin(avail_mask).replace('0b', '')
    fb = _bin(freed_mask).replace('0b', '')
    maxlen = max(len(ab), len(fb))
    ab = ab.zfill(maxlen)   # fills '0'
    fb = fb.zfill(maxlen)

    avail_str = ah + WHT_BOLD(" (0b%s)" % ab)
    freed_str = fh + WHT_BOLD(" (0b%s)" % fb)
    return (avail_str, freed_str)

def generate_slot_map(meta, mask_index=None):
    ''' Generate a map-like string to display the status of all slots in a group.

        If mask_index is set, mask the specified slot in status map.

        Example:
           Slot status map: UUUAAAAFFUUUUUUU[U]UUUUUUUUUUUUU (from slot 29 to slot 0)
            (U: Inuse / A: Available / F: Freed)
    '''

    legend = " (%s: Inuse / %s: Available / %s: Freed)" % (WHT_BOLD("U"), GREEN_BOLD("A"), RED_BOLD("F"))

    avail_mask = meta['avail_mask']
    freed_mask = meta['freed_mask']
    slot_count = int(meta['last_idx']) + 1

    # Generate slot status map
    mapstr = ""
    for idx in range(slot_count):
        avail = avail_mask & 1
        freed = freed_mask & 1
        if not freed and not avail:
            # Inuse
            s = WHT_BOLD("U")
        elif not freed and avail:
            # Available
            s = GREEN_BOLD("A")
        elif freed and not avail:
            # Freed
            s = RED_BOLD("F")
        else:
            s = "?"
        # Mask the slot with index `mask_index` in the map
        if idx == mask_index:
            s = '[' + s + ']'
        mapstr = s + mapstr

        avail_mask >>= 1
        freed_mask >>= 1

    if slot_count > 1:
        mapstr += " (from slot %s to slot %s)" % (BLUE_BOLD(slot_count-1), BLUE_BOLD("0"))

    output = MGNT_BOLD("\nSlot status map: ") + mapstr + '\n' + legend
    return output

# Wrapper functions for Python-builtin hex() and bin()
#
# This part fixes the following error:
#
# pwndbg> python hex(gdb.parse_and_eval('__malloc_context')['secret'])                                                                                                                       
# Traceback (most recent call last):                                                                                                                                                           
#   File "<string>", line 1, in <module>                                                                                                                                                       
# TypeError: 'gdb.Value' object cannot be interpreted as an integer                                                                                                                            
# Error while executing Python code. 
#
# In Ubuntu 16.04 with Python 3.5.2, hex() and other Int-to-Str functions 
# can't convert gdb.Value object to integer type internally. To fix this, 
# int() must be called before calling these functions. 
#
def _hex(x):
    try:
        return hex(x)
    except:
        # Clear sign bit with UINT64_MASK
        # XXX: Does it work in 32-bit arch?
        return hex(int(x) & UINT64_MASK)

def _bin(x):
    try:
        return bin(x)
    except:
        return bin(int(x) & UINT64_MASK)

class Printer():
    ''' A helper class for pretty printing '''
    
    def __init__(self, header_rjust=None, header_ljust=None, header_clr=None, content_clr=None):
        self.HEADER_RJUST = header_rjust
        self.HEADER_LJUST = header_ljust
        self.HEADER_CLR   = header_clr
        self.CONTENT_CLR  = content_clr

    def set(self, header_rjust=None, header_ljust=None, header_clr=None, content_clr=None):
        ''' Set Printer config for coloring and aligning '''
        
        if header_rjust:
            self.HEADER_RJUST = header_rjust
        if header_ljust:
            self.HEADER_LJUST = header_ljust
        if header_clr:
            self.HEADER_CLR   = header_clr
        if content_clr:
            self.CONTENT_CLR  = content_clr

    def print(self, header, content, warning=''):
        ''' Print out message with coloring and aligning '''
        
        header, content, warning = map(str, (header, content, warning))
        
        # Aligning (header)
        if self.HEADER_RJUST:
            header = header.rjust(self.HEADER_RJUST)
        elif self.HEADER_LJUST:
            header = header.ljust(self.HEADER_LJUST)
        header += " :"

        # Coloring (header)
        if self.HEADER_CLR:
            header = self.HEADER_CLR(header)
        # Coloring (warning)
        if warning:
            warning = YLW_BOLD('[' + warning + ']')
        # Coloring (content)
        # Use RED_BOLD for content coloring if warning message is given
            content = RED_BOLD(content)
        elif self.CONTENT_CLR:
            content = self.CONTENT_CLR(content)
    
        # Build and print out message
        if warning:
            ctx = "%s %s %s" % (header, content, warning)
        else:
            ctx = "%s %s"    % (header, content)
        print(ctx)

class MUSL_FUNC():
    '''Each static method in this class simulates the corresponding function in musl-libc C code'''

    @staticmethod
    def get_stride(g):
        # http://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/meta.h?h=v1.2.2#n175

        last_idx  = int(g['last_idx'])
        maplen    = int(g['maplen'])
        sizeclass = int(g['sizeclass'])

        if not last_idx and maplen:
            return maplen * 4096 - UNIT
        elif sizeclass < 48:
            return SIZE_CLASSES[sizeclass] * UNIT
        else:
            # Return None if we failed to get stride
            return None

    @staticmethod
    def is_bouncing(sc):
        # http://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/meta.h?h=v1.2.2#n283

        return (sc - 7 < 32) and int(CTX['bounces'][sc - 7]) >= 100

    @staticmethod
    def okay_to_free(g):
        # http://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/free.c?h=v1.2.2#n38

        if not g['freeable']:
            return False

        sc     = int(g['sizeclass'])
        cnt    = int(g['last_idx']) + 1
        usage  = int(CTX['usage_by_class'][sc])
        stride = MUSL_FUNC.get_stride(g)

        if sc >= 48 or stride < UNIT * SIZE_CLASSES[sc] \
                    or (not g['maplen'])                \
                    or g['next'] != g                   \
                    or (not MUSL_FUNC.is_bouncing(sc))  \
                    or (9 * cnt <= usage and cnt < 20):
            return True

        return False

class Heapinfo(gdb.Command):
    ''' Display mallocng global information, like `heapinfo` command in Pwngdb

        Usage: mheapinfo
    '''
    
    def __init__(self):
        super(Heapinfo, self).__init__("mheapinfo", gdb.COMMAND_USER)
        self.dont_repeat()
    
    def invoke(self, arg, from_tty):
        if not check_mallocng():
            return
        
        printer = Printer(header_clr=MGNT_BOLD, content_clr=WHT_BOLD, header_rjust=16)
        P = printer.print
        
        # Print out useful fields in __malloc_context
        P("secret",           _hex(CTX['secret']))
        P("mmap_counter",     _hex(CTX['mmap_counter']))

        # Print out avaible meta objects
        P("avail_meta",       BLUE_BOLD(_hex(CTX['avail_meta'])) + WHT_BOLD(" (count: %d)" % CTX['avail_meta_count']))
        
        # Walk and print out free_meta chain
        m = head = CTX['free_meta_head']
        if head:
            s = BLUE_BOLD(_hex(head))
            try:
                while head != m['next']:
                    m = m['next']
                    s += WHT_BOLD(" -> ") + BLUE_BOLD(_hex(m))
            except gdb.MemoryError:
                # Most recently accessed memory may be invaild
                s += RED_BOLD(" (Invaild memory)")
            finally:
                P("free_meta", s)
        else:
            P("free_meta", WHT_BOLD("0"))
        
        # Print out avaible meta areas
        P("avail_meta_area", BLUE_BOLD(_hex(CTX['avail_meta_areas'])) + WHT_BOLD(" (count: %d)" % CTX['avail_meta_area_count']))

        # Walk and print out meta_area chain
        ma = CTX['meta_area_head']
        if ma:
            s = BLUE_BOLD(_hex(ma))
            try:
                while ma['next']:
                    ma = ma['next']
                    s += WHT_BOLD(" -> ") + BLUE_BOLD(_hex(ma))
            except gdb.MemoryError:
                # Most recently accessed memory may be invaild
                s += RED_BOLD(" (Invaild memory)")
            finally:
                P("meta_area_head", s)
        else:
            P("meta_area_head", WHT_BOLD("0"))
        if CTX['meta_area_tail']:
            P("meta_area_tail", BLUE_BOLD(_hex(CTX['meta_area_tail'])))
        else:
            P("meta_area_tail", WHT_BOLD("0"))

        # Walk active bin
        printer.set(header_clr=GREEN_BOLD, content_clr=None)
        for i in range(48):
            m = head = CTX['active'][i]
            if head:
                s = BLUE_BOLD(_hex(m))
                try:
                    while True:
                        s += BLUE_BOLD(" (mem: ") + MGNT(_hex(m['mem'])) + BLUE_BOLD(")")
                        if head == m['next']:
                            break
                        m = m['next']
                        s += WHT_BOLD(" -> ") + BLUE_BOLD(_hex(m))
                except gdb.MemoryError:
                    # Most recently accessed memory may be invaild
                    s += RED_BOLD(" (Invaild memory)")
                finally:
                    stride_tips = " [0x%lx]" % (SIZE_CLASSES[i] * UNIT)
                    P("active[%d]" % i, s + stride_tips)

class Magic(gdb.Command):
    ''' Display useful variables and functions in musl-libc, like `magic` command in Pwngdb

        Usage: mmagic
    '''
    
    def __init__(self):
        super(Magic, self).__init__("mmagic", gdb.COMMAND_USER)
        self.dont_repeat()
    
    def invoke(self, arg, from_tty):
        if not check_mallocng():
            return
        
        libcbase = get_libcbase()
        if libcbase == None:
            # Do not calculate offset if libc.so base is not availble
            get_offset = lambda x : int(x)
        else:
            get_offset = lambda x : int(x) - libcbase

        print(WHT_BOLD("====================== FUNCTIONS ======================"))
        ml = max(map(len, MAGIC_FUNCTIONS))
        for name in MAGIC_FUNCTIONS:
            ptr = gdb.parse_and_eval("&%s" % name)
            
            # Print out function offset
            info = MGNT_BOLD(name.ljust(ml)) + BLUE_BOLD(" (0x%lx)" % get_offset(ptr))
            print(info)
        
        print(WHT_BOLD("====================== VARIABLES ======================"))
        ml = max(map(len, MAGIC_VARIABLES))
        for name in MAGIC_VARIABLES:
            ptr = gdb.parse_and_eval("&%s" % name)
            
            value  = ptr.dereference()
            t_size = value.type.sizeof
            # Generate Hex string of the variable value
            # Fill '0' to the string if its length is less than the actual size of value type
            value_hex = _hex(value).replace('0x', '')
            if t_size * 2 > len(value_hex):
                value_hex = (t_size * 2 - len(value_hex)) * '0' + value_hex

            # Print out variable info
            header = MGNT_BOLD(name.ljust(ml)) + BLUE_BOLD(" (0x%lx)" % get_offset(ptr))
            print("%s : 0x%s" % (header, value_hex))

class Findslot(gdb.Command):
    ''' Find a mallocng slot where the given memory is inside. It works by traversing `ctx.meta_area_head` chain.

        Usage: mfindslot <p>
          * p - The memory address to explore. It can be an arbitrary location inside a vaild slot.

    '''

    def __init__(self):
        super(Findslot, self).__init__("mfindslot", gdb.COMMAND_USER)
        self.dont_repeat()

    def search_chain(self, p):
        ''' Find slots where `p` is inside by traversing `ctx.meta_area_head` chain '''

        p = int(p)

        result = []
        try:
            # Traverse every meta object in `meta_area_head` chain
            meta_area = CTX['meta_area_head']
            while meta_area:
                for i in range(int(meta_area['nslots'])):
                    meta = meta_area['slots'][i]
                    if not meta['mem']:
                        # Skip unused
                        continue
                    stride = MUSL_FUNC.get_stride(meta)
                    if stride == None:
                        # Skip invaild stride
                        continue
                    storage     = int(meta['mem']['storage'].address)
                    slot_count  = int(meta['last_idx']) + 1
                    group_start = int(meta['mem'])
                    group_end   = storage + slot_count * stride - IB
                    # Check if `p` is in the range of the group owned by this meta object
                    if p >= group_start and p < group_end:
                        if p >= (storage - IB):
                            # Calculate the index of the slot where `p` is inside
                            slot_index = (p - (storage - IB)) // stride
                        else:
                            # `p` is above the first slot, which means it's not inside of any slots in this group
                            # However, we set the slot index to 0 (the first slot). It's acceptable in most cases.
                            slot_index = 0
                        # We need a pointer (struct meta*), not the object itself
                        m = get_ptr_at(meta.address, 'struct meta')
                        result.append((m, slot_index))
                meta_area = meta_area['next']
        except gdb.MemoryError as e:
            print(RED_BOLD("ERROR:"), str(e))

        return result

    def display_meta(self, meta, index):
        ''' Display slot information (No validation check due to leak of in-band meta) '''

        print(WHT_BOLD("\n================== META ================== ") + "(at %s)" % _hex(meta))
        printer = Printer(header_clr=MGNT_BOLD, content_clr=BLUE_BOLD, header_rjust=13)
        P = printer.print

        avail_mask = meta['avail_mask']
        freed_mask = meta['freed_mask']
        avail_str, freed_str = generate_mask_str(avail_mask, freed_mask)

        # META: Check mem
        P("mem", _hex(meta['mem']))
        # META: Check last_idx
        P("last_idx", meta['last_idx'])
        # META: Check avail_mask
        P("avail_mask", avail_str)
        # META: Check freed_mask
        P("freed_mask", freed_str)

        # META: Check area->check
        area   = get_ptr_value_at(int(meta) & -4096, 'struct meta_area')
        secret = CTX['secret']
        if area['check'] == secret:
            P("area->check", _hex(area['check']))
        else:
            P("area->check", _hex(area['check']),
                        "EXPECT: *(0x%lx) == 0x%lx" % (int(meta) & -4096, secret))

        # META: Check sizeclass
        sc = int(meta['sizeclass'])
        if sc == 63:
            stride = MUSL_FUNC.get_stride(meta)
            if stride != None:
                P("sizeclass", "63 " +  WHT_BOLD(" (stride: 0x%lx)" % stride))
            else:
                P("sizeclass", "63 " +  WHT_BOLD(" (stride: ?)"))
        elif sc < 48:
            sc_stride   = UNIT * SIZE_CLASSES[sc]
            real_stride = MUSL_FUNC.get_stride(meta)
            if real_stride == None:
                stride_tips = WHT_BOLD("(stride: 0x%lx, real_stride: ?)" % sc_stride)
            elif sc_stride != real_stride:
                stride_tips = WHT_BOLD("(stride: 0x%lx, real_stride: 0x%lx)" % (sc_stride, real_stride))
            else:
                stride_tips = WHT_BOLD("(stride: 0x%lx)" % sc_stride)
            P("sizeclass", "%d %s" % (sc, stride_tips))
        else:
            P("sizeclass", sc, "EXPECT: sizeclass < 48 || sizeclass == 63")

        # META: Check maplen
        P("maplen", _hex(meta['maplen']))
        # META: Check freeable
        P("freeable", meta['freeable'])

        # META: Check group allocation method
        if not meta['freeable']:
            # This group is a donated memory.
            # That is, it was placed in an unused RW memory area from a object file loaded by ld.so.
            # (See http://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/donate.c?h=v1.2.2#n10)

            group_addr = int(meta['mem'])

            # Find out which object file in memory mappings donated this memory.
            vmmap = parse_vmmap()
            for mapping in vmmap:
                start, end, objfile = mapping[0], mapping[1], mapping[4]
                if not objfile or objfile.startswith('['):
                    continue
                if group_addr > start and group_addr < end:
                    method = "donated from %s" % WHT_BOLD(objfile)
                    break
            else:
                method = "donated from an unknown object file"
        elif not meta['maplen']:
            # XXX: Find out which group is used.
            method = WHT_BOLD("another group's slot")
        else:
            method = WHT_BOLD("individual mmap")
        print(MGNT_BOLD("\nGroup allocation method : ") + method)

        # Display slot status map
        print(generate_slot_map(meta, index))

    def display_slot(self, p, meta, index):
        ''' Display slot information '''

        print(WHT_BOLD("\n================== SLOT ================== ") )
        printer = Printer(header_clr=MGNT_BOLD, content_clr=BLUE_BOLD, header_rjust=10)
        P = printer.print

        stride = MUSL_FUNC.get_stride(meta)
        slot_start = meta['mem']['storage'][stride * index].address

        # Display the offset from slot to `p`
        offset = int(p - slot_start)
        if offset == 0:
            offset_tips = WHT_BOLD("0")
        elif offset > 0:
            offset_tips = GREEN_BOLD('+' + hex(offset))
        else:
            offset_tips = RED_BOLD(hex(offset))
        offset_tips = " (offset: %s)" % offset_tips

        P("address" , BLUE_BOLD(_hex(slot_start)) + offset_tips)
        P("index"   , index)
        P("stride"  , hex(stride))
        P("meta obj", MGNT(_hex(meta)))

        # Check slot status
        #
        # In mallocng, a slot can be in one of the following status:
        #  INUSE - slot is in use by user
        #  AVAIL - slot is can be allocated to user
        #  FREED - slot is freed
        #
        freed = (meta['freed_mask'] >> index) & 1
        avail = (meta['avail_mask'] >> index) & 1
        if not freed and not avail:
            # Calculate the offset to `user_data` field
            reserved_in_slot_head = (get_ptr_value_at(slot_start - 3, 'uint8_t') & 0xe0) >> 5
            if reserved_in_slot_head == 7:
                cycling_offset = get_ptr_value_at(slot_start - 2, 'uint16_t')
                ud_offset = cycling_offset * UNIT
            else:
                ud_offset = 0

            userdata_ptr = slot_start + ud_offset
            P("status", "%s (userdata --> %s)" % (WHT_BOLD("INUSE"), BLUE_BOLD(_hex(userdata_ptr))))
            print("(HINT: use `mchunkinfo %s` to display more details)" % _hex(userdata_ptr))
        elif not freed and avail:
            P("status", GREEN_BOLD("AVAIL"))
        elif freed and not avail:
            P("status", RED_BOLD("FREED"))
        else:
            P("status", WHT_BOLD("?"))

    def invoke(self, arg, from_tty):
        if not check_mallocng():
            return

        p = gdb.parse_and_eval(arg)
        p = p.cast(gdb.lookup_type('uint8_t').pointer())

        # Find slots by traversing `ctx.meta_area_head` chain
        result = self.search_chain(p)
        if len(result) == 0:
            print(RED_BOLD("Not found.") + " This address may not be managed by mallocng or the slot meta is corrupted.")
            return
        elif len(result) == 1:
            meta, index = result[0]
        else:
            # Multiple slots owning `p` is found.
            # It's normal because mallocng may internally use a large slot to hold group with smaller slots.
            # (See http://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/malloc.c?h=v1.2.2#n260)

            # Find slot which is actually managing `p` (the one with the smallest stride).
            meta, index = result[0]
            for x in result:
                if x[0]['sizeclass'] < meta['sizeclass']:
                    meta, index = x

        print(GREEN_BOLD("Found:"), "slot index is %s, owned by meta object at %s." % (BLUE_BOLD(index), MGNT(_hex(meta))))

        # Display slot and (out-band) meta information about the slot
        try:
            self.display_slot(p, meta, index)
            self.display_meta(meta, index)
        except gdb.error as e:
            print(RED_BOLD("ERROR:"), str(e))
            return

class Chunkinfo(gdb.Command):
    ''' Display infomation of the memory allocated from mallocng, like `chunkinfo` command in Pwngdb

        Usage: mchunkinfo <p>
          * p - A memory address that can be freed by `free()`, usually the one returned from `malloc()`.
                In general, it should be a pointer to the `user_data` field of an *in-use* slot.
                (Use `mfindslot` command to explore a memory address at arbitrary offset of a slot)
    '''
    
    def __init__(self):
        super(Chunkinfo, self).__init__("mchunkinfo", gdb.COMMAND_USER)
        self.dont_repeat()
        
    def parse_ib_meta(self, p):
        ''' Parse 4-byte in-band meta and offset32 '''
        
        ib = {
            "offset16"         :  get_ptr_value_at(p-2, 'uint16_t'),
            "index"            :  get_ptr_value_at(p-3, 'uint8_t') & 0x1f,
            "reserved_in_band" : (get_ptr_value_at(p-3, 'uint8_t') & 0xe0) >> 5,
            "overflow_in_band" :  get_ptr_value_at(p-4, 'uint8_t'),
            "offset32"         :  get_ptr_value_at(p-8, 'uint32_t'),
        }
        return ib
    
    def display_ib_meta(self, p, ib):
        ''' Display in-band meta '''
        
        print(WHT_BOLD("============== IN-BAND META =============="))
        printer = Printer(header_clr=GREEN_BOLD, content_clr=BLUE_BOLD, header_rjust=13)
        P = printer.print   
        
        # IB: Check index
        index = ib['index']
        if index < 0x1f:
            P("INDEX", index)
        else:
            P("INDEX", _hex(index), "EXPECT: index < 0x1f")
            
        # IB: Check reserved_in_band
        reserved_in_band = ib['reserved_in_band']
        if reserved_in_band < 5:
            P("RESERVED", reserved_in_band)
        elif reserved_in_band == 5:
            P("RESERVED", "5" + MGNT_BOLD(" (Use reserved in slot end)"))
        elif reserved_in_band == 6:
            # This slot may be used as a group in mallocng internal.
            # It can't be freed by free() since `reserved_in_band` is illegal.
            # (See https://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/malloc.c?h=v1.2.2#n269)
            P("RESERVED", "%s %s %s" % (RED_BOLD("6"), YLW_BOLD("[EXPECT: <= 5]"), MGNT_BOLD("(This slot may internally used as a group)")))
        else:
            P("RESERVED", _hex(reserved_in_band), "EXPECT: <= 5") 

        # IB: Check overflow
        offset16 = ib['offset16']
        overflow_in_band = ib['overflow_in_band']
        if not overflow_in_band:
            group_ptr = p - (offset16 + 1) * UNIT
            P("OVERFLOW", 0)
            P("OFFSET_16", "%s (group --> %s)" % (_hex(offset16), _hex(group_ptr)))
        else:
            # `offset32` can be used as the offset to group object 
            # instead of `offset16` in IB if `overflow_in_band` is not NULL. 
            # It is unlikely to happen in musl-libc for this feature 
            # is only used in aligned_alloc() and comes with restriction: 
            #   offset32  > 0xffff and offset16 == 0
            offset32  = ib['offset32']
            group_ptr = p - (offset32 + 1) * UNIT
            P("OVERFLOW", WHT_BOLD(_hex(overflow_in_band)) + MGNT_BOLD(" (Use 32-bit offset)"))
            if offset32 > 0xffff:
                P("OFFSET_32", "%s (group --> %s)" % (_hex(offset32), _hex(group_ptr)))
            else:
                P("OFFSET_32", _hex(offset32), "EXPECT: > 0xffff")
            if offset16:
                P("OFFSET_16", _hex(offset16), "EXPECT: *(uint16_t*)(%s) == 0]" % _hex(p - 2))
    
    def display_group(self, group):
        ''' Display group information '''

        print(WHT_BOLD("\n================= GROUP ================== ") + "(at %s)" % _hex(group.address))
        printer = Printer(header_clr=CYAN_BOLD, content_clr=BLUE_BOLD, header_rjust=13)
        P = printer.print

        P("meta",       _hex(group['meta']))
        P("active_idx", int(group['active_idx']))

    def display_meta(self, ib, group):
        ''' Display (out-band) meta information '''
        
        meta  = group['meta']
        index = ib['index']
        if not ib['overflow_in_band']:
            offset = ib['offset16']
        else:
            offset = ib['offset32']
        
        print(WHT_BOLD("\n================== META ================== ") + "(at %s)" % _hex(meta))
        printer = Printer(header_clr=MGNT_BOLD, content_clr=BLUE_BOLD, header_rjust=13)
        P = printer.print   
        
        # META: Check mem
        mem = meta['mem']
        if group.address == mem:
            P("mem", _hex(mem))
        else:
            P("mem", _hex(mem), "EXPECT: 0x%lx" % group.address)
            
        # META: Check last_idx
        last_idx = meta['last_idx']
        if index <= last_idx:
            P("last_idx", last_idx)
        else:
            P("last_idx", last_idx, "EXPECT: index <= last_idx")
        
        avail_mask = meta['avail_mask']
        freed_mask = meta['freed_mask']
        avail_str, freed_str = generate_mask_str(avail_mask, freed_mask)
        
        # META: Check avail_mask
        if not (avail_mask & (1 << index)):
            P("avail_mask", avail_str)
        else:
            P("avail_mask", avail_str, "EXPECT: !(avail_mask & (1<<index))")
                        
        # META: Check freed_mask
        if not (freed_mask & (1 << index)):
            P("freed_mask", freed_str)
        else:
            P("freed_mask", freed_str, "EXPECT: !(freed_mask & (1<<index))")
                        
        # META: Check area->check
        area   = get_ptr_value_at(int(meta) & -4096, 'struct meta_area')
        secret = CTX['secret']
        if area['check'] == secret:
            P("area->check", _hex(area['check']))
        else:
            P("area->check", _hex(area['check']), 
                        "EXPECT: *(0x%lx) == 0x%lx" % (int(meta) & -4096, secret))
                        
        # META: Check sizeclass
        sc = int(meta['sizeclass'])
        if sc == 63:
            stride = MUSL_FUNC.get_stride(meta)
            if stride != None:
                P("sizeclass", "63 " +  WHT_BOLD(" (stride: 0x%lx)" % stride))
            else:
                P("sizeclass", "63 " +  WHT_BOLD(" (stride: ?)"))
        elif sc < 48:
            sc_stride   = UNIT * SIZE_CLASSES[sc]
            real_stride = MUSL_FUNC.get_stride(meta)
            if real_stride == None:
                stride_tips = WHT_BOLD("(stride: 0x%lx, real_stride: ?)" % sc_stride)
            elif sc_stride != real_stride:
                stride_tips = WHT_BOLD("(stride: 0x%lx, real_stride: 0x%lx)" % (sc_stride, real_stride))
            else:
                stride_tips = WHT_BOLD("(stride: 0x%lx)" % sc_stride)
            bad = 0
            if not (offset >= SIZE_CLASSES[sc] * index):
                P("sizeclass", "%d %s" % (sc, stride_tips), 
                            "EXPECT: offset >= SIZE_CLASSES[sizeclass] * index")
                bad = 1
            if not (offset < SIZE_CLASSES[sc] * (index + 1)):
                P("sizeclass", "%d %s" % (sc, stride_tips), 
                            "EXPECT: offset < SIZE_CLASSES[sizeclass] * (index + 1)")
                bad = 1
            if not bad:
                P("sizeclass", "%d %s" % (sc, stride_tips))
        else:
            P("sizeclass", sc, "EXPECT: sizeclass < 48 || sizeclass == 63")
                                
        # META: Check maplen
        maplen = int(meta['maplen'])
        if maplen:
            if offset <= (maplen * (4096 // UNIT)) - 1:
                P("maplen", _hex(maplen))
            else:
                P("maplen", _hex(maplen), "EXPECT: offset <= maplen * %d - 1" % (4096 // UNIT))
        else:
            P("maplen", 0)
        
        # META: Check freeable
        P("freeable", meta['freeable'])

        # META: Check group allocation method
        if not meta['freeable']:
            # This group is a donated memory.
            # That is, it was placed in an unused RW memory area from a object file loaded by ld.so.
            # (See http://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/donate.c?h=v1.2.2#n10)

            group_addr = int(group.address)

            # Find out which object file in memory mappings donated this memory.
            vmmap = parse_vmmap()
            for mapping in vmmap:
                start, end, objfile = mapping[0], mapping[1], mapping[4]
                if not objfile or objfile.startswith('['):
                    continue
                if group_addr > start and group_addr < end:
                    method = "donated from %s" % WHT_BOLD(objfile)
                    break
            else:
                method = "donated from an unknown object file"
        elif not meta['maplen']:
            # XXX: Find out which group is used.
            method = WHT_BOLD("another group's slot")
        else:
            method = WHT_BOLD("individual mmap")
        print(MGNT_BOLD("\nGroup allocation method : ") + method)

        # Display slot status map
        print(generate_slot_map(meta, index))

    def display_nontrivial_free(self, ib, group):
        ''' Display the result of nontrivial_free() '''
        
        printer = Printer(header_clr=MGNT_BOLD, content_clr=GREEN_BOLD)
        P = printer.print
        print()
        
        print_dq = print_fg = print_fm = 0
        
        meta      = group['meta']
        sizeclass = int(meta['sizeclass'])
        index     = int(ib['index'])
        
        mask = int(meta['freed_mask'] | meta['avail_mask'])
        slf  = (1 << index) & UINT32_MASK
        if mask + slf == (2 << meta['last_idx']) - 1 and MUSL_FUNC.okay_to_free(meta):
            if meta['next']:
                if sizeclass < 48:
                    P("Result of nontrivial_free()", "dequeue, free_group, free_meta")
                else:
                    P("Result of nontrivial_free()", "dequeue, free_group, free_meta", 
                                                        "EXPECT: sizeclass < 48")
                print_dq = print_fg = print_fm = 1
            else:
                P("Result of nontrivial_free()", "free_group, free_meta")
                print_fg = print_fm = 1
        elif not mask and CTX['active'][sizeclass] != meta:
            if sizeclass < 48:
                P("Result of nontrivial_free()", "queue (active[%d])" % sizeclass)
            else:
                P("Result of nontrivial_free()", "queue (active[%d])" % sizeclass,
                                                "EXPECT: sizeclass < 48")
        else:
            P("Result of nontrivial_free()", WHT_BOLD("Do nothing"))
        
        # dequeue
        if print_dq:
            print(GREEN_BOLD("  dequeue:"))
            prev_next = MGNT('*' + _hex(meta['prev']['next'].address))
            prev_next = BLUE_BOLD("prev->next(") + prev_next + BLUE_BOLD(")")
            next_prev = MGNT('*' + _hex(meta['next']['prev'].address))
            next_prev = BLUE_BOLD("next->prev(") + next_prev + BLUE_BOLD(")")
            next      = BLUE_BOLD("next(") + MGNT(_hex(meta['next'])) + BLUE_BOLD(")")
            prev      = BLUE_BOLD("prev(") + MGNT(_hex(meta['prev'])) + BLUE_BOLD(")")
            print("  \t%s = %s" % (prev_next, next))    # prev->next(XXX) = next(XXX)
            print("  \t%s = %s" % (next_prev, prev))    # next->prev(XXX) = prev(XXX)
        # free_group
        if print_fg:
            print(GREEN_BOLD("  free_group:"))
            if meta['maplen']:
                free_method = "munmap (len=0x%lx)" % (int(meta['maplen']) * 4096)
            else:
                free_method = "nontrivial_free()"
            print(" \t%s%s%s%s" %(BLUE_BOLD("group object at "), MGNT(_hex(meta['mem'])), 
                                BLUE_BOLD(" will be freed by " ), CYAN_BOLD(free_method)))
        # free_meta
        if print_fm:
            print(GREEN_BOLD("  free_meta:"))
            print(" \t%s%s%s" %(BLUE_BOLD("meta object at "), MGNT(_hex(meta)), 
                                BLUE_BOLD(" will be freed and inserted into free_meta chain")))
        
    def display_slot(self, p, ib, slot_start, slot_end):
        ''' Display slot information '''
        
        print(WHT_BOLD("\n================== SLOT ================== ") + "(at %s)" % _hex(slot_start))
        printer = Printer(header_clr=BLUE_BOLD, content_clr=WHT_BOLD, header_rjust=20)
        P = printer.print
        
        # SLOT: Check cycling offset
        reserved_in_slot_head = (get_ptr_value_at(slot_start - 3, 'uint8_t') & 0xe0) >> 5
        if reserved_in_slot_head == 7:
            # If `R` is 7, it indicates that slot header is used to store cycling offset (in `OFF` field)
            # (See http://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/meta.h?h=v1.2.2#n217)
            cycling_offset = get_ptr_value_at(slot_start - 2, 'uint16_t') # `OFF`
        else:
            # Else, slot header is now occupied by in-band meta.
            # In this case, `userdata` will be located at the beginning of slot.
            cycling_offset = 0
        userdata_ptr = slot_start + cycling_offset * UNIT
        P("cycling offset", "%s (userdata --> %s)" % (_hex(cycling_offset), _hex(userdata_ptr)))
        
        # SLOT: Check reserved
        reserved_in_band = ib['reserved_in_band']
        if reserved_in_band < 5:
            reserved = reserved_in_band
        elif reserved_in_band == 5:
            reserved_in_slot_end = get_ptr_value_at(slot_end - 4, 'uint32_t')
            if reserved_in_slot_end >= 5:
                reserved = reserved_in_slot_end
            else:
                P("reserved (slot end)", _hex(reserved_in_slot_end), "EXPECT: >= 5")
                reserved = -1
        else:
            P("reserved (in-band)", _hex(reserved_in_band), "EXPECT: <= 5")
            reserved = -1
        
        # SLOT: Check nominal size
        if reserved != -1:
            if reserved <= slot_end - p:
                nominal_size = slot_end - reserved - p
                P("nominal size",  _hex(nominal_size))
                P("reserved size", _hex(reserved))
            else:
                P("nominal size",  "N/A (reserved size is invaild)")
                P("reserved size", _hex(reserved), "EXPECT: <= %s" % _hex(slot_end - p))
                reserved = -1
        else:
            P("nominal size",  "N/A (reserved size is invaild)")
        
        # SLOT: Check OVERFLOWs
        if reserved != -1:
            ud_overflow = get_ptr_value_at(slot_end - reserved, 'uint8_t')
            if not ud_overflow:
                P("OVERFLOW (user data)", 0)
            else:
                P("OVERFLOW (user data)", _hex(ud_overflow), 
                                "EXPECT: *(uint8_t*)(%s) == 0" % _hex(slot_end - reserved))
            if reserved >= 5:
                rs_overflow = get_ptr_value_at(slot_end - 5, 'uint8_t')
                if not rs_overflow:
                    P("OVERFLOW  (reserved)", 0)
                else:
                    P("OVERFLOW  (reserved)", _hex(rs_overflow),
                                "EXPECT: *(uint8_t*)(%s) == 0" % _hex(slot_end - 5))
        else:
            P("OVERFLOW (user data)", "N/A (reserved size is invaild)")
            P("OVERFLOW  (reserved)", "N/A (reserved size is invaild)")
        ns_overflow = get_ptr_value_at(slot_end, 'uint8_t')         
        if not ns_overflow:
            P("OVERFLOW (next slot)", 0)
        else:
            P("OVERFLOW (next slot)", _hex(ns_overflow), 
                                "EXPECT: *(uint8_t*)(%s) == 0" % _hex(slot_end))
            
    def invoke(self, arg, from_tty):
        if not check_mallocng():
            return
        
        p = gdb.parse_and_eval(arg)
        p = p.cast(gdb.lookup_type('uint8_t').pointer()) 
        
        # Parse in-band meta
        try:
            ib = self.parse_ib_meta(p)
        except gdb.error as e:
            print(RED_BOLD("ERROR:"), str(e))
            return
        
        # Display in-band meta information
        self.display_ib_meta(p, ib)
        
        # Get group struct object
        if not ib['overflow_in_band']:
            offset = ib['offset16']
        else:
            offset = ib['offset32']
        addr  = p - (offset + 1) * UNIT
        group = get_ptr_value_at(addr, 'struct group')
        
        # Display group and (out-band) meta information
        try:
            self.display_group(group)
            self.display_meta(ib, group)
        except gdb.error as e:
            print(RED_BOLD("ERROR:"), str(e))
            return

        # Check if we have vaild stride / sizeclass
        stride = MUSL_FUNC.get_stride(group['meta'])
        if stride != None:
            # Display the result of nontrivial_free()
            self.display_nontrivial_free(ib, group)
            
            # Compute the beginning and the ending address of slot
            slot_start = group['storage'][stride * ib['index']].address
            slot_end   = slot_start + stride - IB
            
            # Display slot information
            try:
                self.display_slot(p, ib, slot_start, slot_end)
            except gdb.error as e:
                print(RED_BOLD("ERROR:"), str(e))
                return
        else:
            print(RED_BOLD("\nCan't get slot and nontrivial_free() information due to invaild sizeclass"))

# Register GDB commands
Heapinfo()
Magic()
Chunkinfo()
Findslot()
