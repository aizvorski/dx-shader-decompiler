"""
Decompiler for DirectX shader code.

Copyright (c) 2013-2014 CiiNOW Inc.
Written by Alex Izvorski <aizvorski@gmail.com>, <alex@ciinow.com>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""


"""
This is currently supports decompiling pixel shader and vertex shader 3_0

Reference for the assembly language: http://msdn.microsoft.com/en-us/library/bb219840%28v=vs.85%29.aspx
Reference for the machine language: http://msdn.microsoft.com/en-us/library/windows/hardware/ff552891%28v=vs.85%29.aspx

Compile:
fxc.exe fx_examples/PP_ColorBloomH.fx /E PostProcessPS /T ps_3_0 /Fx test.txt
(note, this produces a text file containing the hex of the compiled shaders, but binary works as input also)

Decompile:
python dx-shader-decompiler.py test.txt
"""


from bitstring import *
import pdb
import sys
import re
import fileinput

opcodes_list = [
    'nop',
    'mov',
    'add',
    'sub',
    'mad',
    'mul',
    'rcp',
    'rsq',
    'dp3',
    'dp4',
    'min',
    'max',
    'slt',
    'sge',
    'exp',
    'log',
    'lit',
    'dst',
    'lrp',
    'frc',
    'm4x4',
    'm4x3',
    'm3x4',
    'm3x3',
    'm3x2',
    'call',
    'callnz',
    'loop',
    'ret',
    'endloop',
    'label',
    'dcl',
    'pow',
    'crs',
    'sgn',
    'abs',
    'nrm',
    'sincos',
    'rep',
    'endrep',
    'if',
    'ifc',
    'else',
    'endif',
    'break',
    'breakc',
    'mova',
    'defb',
    'defi',
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    'texcoord', # 64
    'texkill',
    'texld', # tex in ps < 2_0
    'texbem',
    'texbeml',
    'texreg2ar',
    'texreg2gb',
    'texm3x2pad',
    'texm3x2tex',
    'texm3x3pad',
    'texm3x3tex',
    'reserved0',
    'texm3x3spec',
    'texm3x3vspec',
    'expp',
    'logp',
    'cnd',
    'def',
    'texreg2rgb',
    'texdp3tex',
    'texm3x2depth',
    'texdp3',
    'texm3x3',
    'texdepth',
    'cmp',
    'bem',
    'dp2add',
    'dsx',
    'dsy',
    'texldd',
    'setp',
    'texldl',
    'breakp',
    ]


# http://msdn.microsoft.com/en-us/library/ff569707%28v=vs.85%29.aspx
register_type_list = [
    'temp',
    'input',
    'const',
    'texture',
    #'addr', # Duplicate of texture
    'rastout',
    'attrout',
    #'texcrdout', # Duplicate of output
    'output',
    'constint',
    'colorout',
    'depthout',
    'sampler',
    'const2',
    'const3',
    'const4',
    'constbool',
    'loop',
    'tempfloat16',
    'misctype',
    'label',
    'predicate',
    ]

register_type_mnemonic_list = [
    'r',
    'v',
    'c',
    't',
    #'a', # Duplicate of texture
    'rastout', # o ?
    'attrout', # o ?
    #'oT', # Duplicate of output
    'o',
    'i',
    'oC',
    'oDepth',
    's',
    'const2',
    'const3',
    'const4',
    'b',
    'aL',
    'tempfloat16',
    'misctype',
    'label',
    'predicate',
    ]

source_modifier_mnemonic_list = [
    None, # 0x0  None
    '-R', # 0x1  Negate
    None, # 0x2  Bias
    None, # 0x3  Bias and negate
    None, # 0x4  Sign (bx2)
    None, # 0x5  Sign (bx2) and negate
    None, # 0x6  Complement
    None, # 0x7  x2 (PS 1_4)
    None, # 0x8  x2 and negate (PS 1_4)
    None, # 0x9  dz (divide through by Z component PS 1_4)
    None, # 0xa  dw (divide through by W component PS 1_4)
    'abs(R)', # 0xb  abs(x) compute absolute value
    None, # 0xc  -abs(x) compute absolute value and negate
    None, # 0xd  NOT. Applied only to the predication register, which is BOOL. Therefore, it is logical NOT.
    ]

result_modifier_mnemonic_list = [
    None,
    '_sat',
    '_pp',
    '_centroid',
    ]

texture_type_mnemonic_list = [
    '', # None,
    '', # Unused
    '2d',
    'cube',
    'volume',
    ]
    
# http://msdn.microsoft.com/en-us/library/windows/desktop/bb172534(v=vs.85).aspx    
usage_type_list = [
    'position',
    'blendweight',
    'blendindices',
    'normal',
    'psize',
    'texcoord',
    'tangent',
    'binormal',
    'tessfactor',
    'positiont',
    'color',
    'fog',
    'depth',
    'sample',
    ]
    
class OpCodeToken():
# Instruction:
# [15:00] opcode
# [23:16] specific controls
# [27:24] ps >= 2_0: dword size
# [28] ps >= 2_0: predicated instruction
# [29] 0
# [30] ps < 2_0: co issue bit
# [31] 0

    def __init__(self, token):
        self.token = token

        bs = BitStream(uint=token, length=32)
        junk, self.is_predicated, self.instruction_size, self.specific_controls, self.operation_code = bs.unpack('uint:3, bool, uint:4, uint:8, uint:16')

        # HACK comments: should be better way to handle?
        if self.operation_code == 0xFFFE:
            junk, self.instruction_size, self.operation_code = bs.unpack('uint:1, uint:15, uint:16')

        # print "operation_code=%d (%s) instruction_size=%d specific_controls=%d is_predicated=%d" % (operation_code, operation_code_name, instruction_size, specific_controls, is_predicated)

    def get_name(self):
        s = ''
        if self.operation_code < len(opcodes_list):
            s += opcodes_list[ self.operation_code ]
        elif self.operation_code == 0xFFFE:
            s += 'comment'
        else:
            s += "?"
        return s

    def __str__(self):
        return "\n" + self.get_name()

class SourceParamToken():
# Source:
# [10:0] Reg Number
# [12:11] Register Type bits 3,4
# [13] relative addressing bit (0 for all versions except vs3.0)
# [15:14] MBZ
# [23:16] Swizzle [17:16] -x, [19:18] - y etc (0 means X, 1 means Y, 2 means Z, 3-W)
# [27:24] Modifier - 1=Negate, 0xb=Abs(), 0xd=Logical BOOL on predicate reg
# [30:28] Register Type bits 0,1,2
# [31] 1

    def __init__(self, token):
        self.token = token

        bs = BitStream(uint=token, length=32)
        junk1, regtype1, self.source_modifier, self.swizzle, junk2, self.is_relative_addressing, regtype2, self.register_number = bs.unpack('uint:1, uint:3, uint:4, uint:8, uint:2, bool, uint:2, uint:11')

        self.register_type = regtype2 << 3 | regtype1

        # print "src register_number=%d register_type=%d (%s) swizzle=%d source_modifier=%d is_relative_addressing=%d" % (register_number, register_type, register_type_list[register_type], swizzle, source_modifier, is_relative_addressing)

    def swizzle_to_str(self, swizzle):
        s = ''
        for i in range(4):
            sc = (swizzle & (0x03<<(i*2))) >> (i*2)
            if   sc == 0x00: s += 'x'
            elif sc == 0x01: s += 'y'
            elif sc == 0x02: s += 'z'
            elif sc == 0x03: s += 'w'
            else: s += '?'
        if s == 'xxxx': s = 'x'
        if s == 'yyyy': s = 'y'
        if s == 'zzzz': s = 'z'
        if s == 'wwww': s = 'w'
        return s

    def __str__(self):
        s = ''
        if self.register_type < len( register_type_mnemonic_list ):
            s = register_type_mnemonic_list[ self.register_type ] + str(self.register_number)
        sws = self.swizzle_to_str( self.swizzle )
        if sws != 'xyzw': s += '.' + sws
        if self.source_modifier < len( source_modifier_mnemonic_list ):
            if source_modifier_mnemonic_list[ self.source_modifier ] == '-R': s = '-' + s
            if source_modifier_mnemonic_list[ self.source_modifier ] == 'abs(R)': s = 'abs(' + s + ')'
        return s

class DestParamToken():
# Destination:
# [10:0] Reg Number
# [12:11] Register Type bits 3,4
# [13] relative addressing bit (0 for all versions except vs3.0)
# [15:14] MBZ
# [19:16] WriteMask
# [23:20] Modifier 1-sat, 2-pp, 3-centroid
# [27:24] MBZ (used for ps < 2.0)
# [30:28] Register Type bits 0,1,2
# [31] 1

    def __init__(self, token):
        self.token = token

        bs = BitStream(uint=token, length=32)
        junk1, regtype1, junk2, self.result_modifier, self.write_mask, junk3, self.is_relative_addressing, regtype2, self.register_number =  bs.unpack('uint:1, uint:3, uint:4, uint:4, uint:4, uint:2, bool, uint:2, uint:11')

        self.register_type = regtype2 << 3 | regtype1

        # print "dest register_number=%d register_type=%d (%s) write_mask=%d (%s) is_relative_addressing=%d" % (register_number, register_type, register_type_list[register_type], write_mask, write_mask_to_str(write_mask), is_relative_addressing)

    def write_mask_to_str(self, write_mask):
        s = ''
        if write_mask & 1<<0: s += 'x'
        if write_mask & 1<<1: s += 'y'
        if write_mask & 1<<2: s += 'z'
        if write_mask & 1<<3: s += 'w'
        return s

    def __str__(self):
        s = register_type_mnemonic_list[ self.register_type ] + str(self.register_number)
        wms = self.write_mask_to_str( self.write_mask )
        if wms != 'xyzw': s += '.' + wms
        # TODO these usually are part of the instruction mnemonic
        # if self.result_modifier < len( result_modifier_mnemonic_list ): s = result_modifier_mnemonic_list[ self.result_modifier ] + ' ' + s
        return s

class VersionToken:
    def __init__(self, token): 
        self.token = token
        bs = BitStream(uint=token, length=32)
        junk1, self.major, self.minor =  bs.unpack('uint:16, uint:8, uint:8')

    def __str__(self): 
        # FIXME could be ps or vs
        return 'ps_%d_%d' % (self.major, self.minor)

class EndToken:
    def __init__(self, token): self.token = token
    def __str__(self): return "\nend"

class CommentToken:
    def __init__(self, token): 
        self.token = token
        bs = BitStream(uint=token, length=32)
        c1, c2, c3, c4 = bs.unpack('uint:8, uint:8, uint:8, uint:8')
        self.comment = chr(c1) + chr(c2) + chr(c3) + chr(c4)
    def __str__(self): 
        return ""
        # return self.comment

class DclInfoToken:
    def __init__(self, token): 
        self.token = token
        bs = BitStream(uint=token, length=32)
        junk1, self.sampler_texture_type, junk2, self.usage_index, junk3, self.usage = bs.unpack("uint:1, uint:4, uint:7, uint:4, uint:12, uint:4")
        
    def __str__(self):
        if(self.sampler_texture_type == 0):
            return "" + usage_type_list[ self.usage ] + repr( self.usage_index )
        else:
            return "" + texture_type_mnemonic_list[ self.sampler_texture_type ]
        
        # return "%08x" % self.token

class ConstFloatToken:
    def __init__(self, token): 
        self.token = token
        bs = BitStream(uint=token, length=32)
        self.floatval, = bs.unpack('floatbe:32')

    def __str__(self): return "%f" % self.floatval

class Shader():
    def __init__(self, tokens):
        self.tokens = []
        self.parsed_tokens = []

        opcode = None
        opcode_idx = 0

        for i in range(len( tokens )):
            token = tokens[ i ]

            if i == 0:
                if token & 0xFFFF0000 == 0xFFFF0000:
                    self.parsed_tokens.append( VersionToken( token ) )
                    continue
                # else: throw

            if opcode and i <= opcode_idx + opcode.instruction_size:
                if opcode.get_name() == 'comment': 
                    self.parsed_tokens.append( CommentToken( token ) )
                elif opcode.get_name() == 'dcl' and i == opcode_idx + 1: 
                   self.parsed_tokens.append( DclInfoToken( token ) )
                elif opcode.get_name() == 'dcl' and i == opcode_idx + 2: 
                   self.parsed_tokens.append( DestParamToken( token ) )
                elif opcode.get_name() == 'def' and i != opcode_idx + 1: 
                   self.parsed_tokens.append( ConstFloatToken( token ) )
                elif opcode.get_name() != 'ifc' and i == opcode_idx + 1:  
                    self.parsed_tokens.append( DestParamToken( token ) )
                else: 
                    self.parsed_tokens.append( SourceParamToken( token ) )
                continue
            
            if token == 0x0000FFFF:
                self.parsed_tokens.append( EndToken( token ) )
                # if i != len( tokens )-1: throw
                break

            opcode = OpCodeToken( token )
            opcode_idx = i
            self.parsed_tokens.append( opcode )
            

    def __str__(self):
        s = ''
        for i in range(len( self.parsed_tokens )):
            s += str( self.parsed_tokens[ i ] ) + " "
        return s



# parse format produced by fxc.exe /Fx
# asm_code = []
# for line in fileinput.input():
#     m = re.search('// [0-9a-f]{4}:  (\w{8})  (\w{8})?  (\w{8})?  (\w{8})?', line)
#     if m:
#         t1, t2, t3, t4 = m.groups()
#         if t1: asm_code.append( t1 )
#         if t2: asm_code.append( t2 )
#         if t3: asm_code.append( t3 )
#         if t4: asm_code.append( t4 )

for line in fileinput.input():
    sys.stdout.write("Tokens: " + line)
    asm_code = re.findall('[0-9a-f]{8}', line)
    asm_code = map(lambda x: int(x, 16), asm_code)
    sys.stdout.write("Assembly: \n")
    sh = Shader(asm_code)
    sys.stdout.write( str( sh ) )
    sys.stdout.write("\n\n")
    sys.stdout.flush()
