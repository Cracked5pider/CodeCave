from enum import Flag

class RegFlags(Flag):
    REG_NONE                        = 0
    REG_SZ                          = 1
    REG_EXPAND_SZ                   = 2
    REG_BINARY                      = 3
    REG_DWORD                       = 4
    REG_DWORD_LITTLE_ENDIAN         = 4
    REG_DWORD_BIG_ENDIAN            = 5
    REG_LINK                        = 6
    REG_MULTI_SZ                    = 7
    REG_RESOURCE_LIST               = 8
    REG_FULL_RESOURCE_DESCRIPTOR    = 9
    REG_RESOURCE_REQUIREMENTS_LIST  = 10
    REG_QWORD                       = 11
    REG_QWORD_LITTLE_ENDIAN         = 11

def flags_set(num):
    return [sus.name for sus in RegFlags if num & sus.value]

print(flags_set(0x4000004))