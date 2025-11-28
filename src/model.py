from enum import IntEnum

class FuncType(IntEnum):
    ImportFunc = 0x0000,
    ExportFunc = 0x0001,
    VftableFunc = 0x0002,
    COMVTFunc = 0x0004,