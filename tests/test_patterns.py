"""Native tests of the production matcher with an external EXE and synthetic variants."""
import ctypes as C,itertools,json,struct,sys,time
from pathlib import Path
PROJECT=Path(__file__).resolve().parents[1]
import pefile,capstone

class Patch(C.Structure):
    _fields_=[('site',C.c_void_p),('original',C.c_ubyte*24),('replacement',C.c_ubyte*24),('length',C.c_uint32),('owner',C.c_ubyte),('new_count',C.c_ubyte),('count_offset',C.c_int32),('already',C.c_int)]
LIB=C.CDLL(str(Path(__file__).with_name('matcher_host.so')))
LIB.scan_host.argtypes=[C.c_void_p,C.POINTER(C.c_uint32),C.POINTER(C.c_uint32),C.c_uint32,C.POINTER(Patch)]
LIB.remove_body_host.argtypes=[C.c_void_p]
def scan(image,spans):
    buf=C.create_string_buffer(bytes(image));starts=(C.c_uint32*len(spans))(*[x[0] for x in spans]);sizes=(C.c_uint32*len(spans))(*[x[1] for x in spans]);p=Patch()
    n=LIB.scan_host(buf,starts,sizes,len(spans),C.byref(p))
    return n,p,p.site-C.addressof(buf) if n else None

class Asm:
    def __init__(self,rva):self.rva=rva;self.b=bytearray();self.labels={};self.fix=[]
    def emit(self,*data):self.b.extend(data)
    def label(self,name):self.labels[name]=self.rva+len(self.b)
    def mem(self,op,reg,base,disp=0,index=None,force32=False):
        mod=2 if force32 or not -128<=disp<=127 else (0 if disp==0 and base!=5 else 1)
        rm=4 if index is not None or base==4 else base
        self.emit(op,(mod<<6)|(reg<<3)|rm)
        if rm==4:self.emit((2<<6)|((index if index is not None else 4)<<3)|base)
        if mod==1:self.emit(disp&255)
        elif mod==2:self.b.extend(struct.pack('<i',disp))
    def rr(self,op,a,b):self.emit(op,0xc0|(a<<3)|b)
    def call(self,target):
        at=self.rva+len(self.b);self.emit(0xe8);self.b.extend(struct.pack('<i',target-(at+5)))
    def jump(self,cc,label,near=False):
        if near:self.emit(0x0f,0x80+cc);n=4
        else:self.emit(0x70+cc);n=1
        self.fix.append((len(self.b),n,label));self.b.extend(bytes(n))
    def finish(self):
        for at,n,label in self.fix:
            target=self.labels[label] if isinstance(label,str) else label
            value=target-(self.rva+at+n)
            self.b[at:at+n]=struct.pack('<i' if n==4 else '<b',value)
        return bytes(self.b)

def fixture(helper,owner=2,retained=7,scanreg=6,array=3,array_disp=0x44,flag_disp=0xd8,near=False,rva=0x1100,wrapped=True):
    free=[r for r in [0,1,2] if r!=owner];data,copy_data=free
    a=Asm(rva);a.emit(0x55,0x8b,0xec)
    a.mem(0x8d,array,owner,array_disp)
    a.label('loop');a.mem(0x8b,data,array);a.mem(0x8b,data,data,index=scanreg)
    a.rr(0x85,data,data);a.jump(4,'skip',near)
    a.mem(0xf7,0,data,flag_disp);a.b.extend(struct.pack('<I',0x400));a.jump(5,'skip',near)
    a.rr(0x3b,retained,scanreg);a.jump(4,'copy',near)
    a.emit(0x50+retained);a.rr(0x8b,1,array);a.call(0x3800)
    a.mem(0x8b,owner,5,-4)
    a.label('copy');a.mem(0x8b,copy_data,array);a.emit(0x40+retained)
    a.mem(0x8b,data,copy_data,index=scanreg)
    a.mem(0x89,data,copy_data,-4,index=retained)
    a.label('skip');a.emit(0x40+scanreg)
    a.mem(0x3b,scanreg,owner,array_disp+4);a.jump(12,'loop',near)
    a.emit(0x58+array)
    a.label('tail');a.mem(0x8b,data,owner,array_disp+4);a.rr(0x3b,retained,data);a.jump(4,'end',near)
    a.label('patch');a.rr(0x2b,data,retained);a.emit(0x50+data,0x50+retained)
    a.mem(0x8d,1,owner,array_disp);a.call(0x3000 if wrapped else 0x2800)
    a.label('end');a.emit(0x58+retained,0x58+scanreg,0x8b,0xe5,0x5d,0xc3)
    code=a.finish();image=bytearray(b'\xcc'*0x6000)
    image[rva:rva+len(code)]=code
    # External direct calls in the removal routine are moved with the fixture.
    moved=bytearray(helper)
    cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
    for i in cs.disasm(helper,0):
        if i.bytes[0]==0xe8:struct.pack_into('<i',moved,i.address+1,0x3800-(0x2800+i.address+5))
    image[0x2800:0x2800+len(moved)]=moved
    w=Asm(0x3000);w.emit(0x55,0x8b,0xec,0x56,0x8b,0xf1,0xff,0x75,0x0c,0x8b,0xce,0xff,0x75,0x08);w.call(0x2800);w.emit(0x5e,0x5d,0xc2,8,0)
    image[0x3000:0x3000+len(w.b)]=w.finish();image[0x3800]=0xc3
    expected=Asm(0);expected.mem(0x89,retained,owner,array_disp+4)
    length=a.labels['end']-a.labels['patch']
    replacement=bytes(expected.b)+b'\x90'*(length-len(expected.b))
    return image,a.labels['patch'],replacement,a.labels

def real_input():
    if len(sys.argv)<2:raise SystemExit('Usage: python tests/test_patterns.py /path/to/Bioshock2HD.exe')
    path=Path(sys.argv[1])
    pe=pefile.PE(str(path));image=pe.get_memory_mapped_image()
    spans=[(s.VirtualAddress,s.Misc_VirtualSize) for s in pe.sections if s.Characteristics&0x20000000]
    t=time.perf_counter();n,p,at=scan(image,spans);elapsed=time.perf_counter()-t
    assert n==1 and not p.already
    cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);cs.detail=True
    code=list(cs.disasm(image[at:at+p.length],at));wrapper=code[-1].operands[0].imm
    calls=[]
    for insn in cs.disasm(image[wrapper:wrapper+256],wrapper):
        if insn.bytes[0]==0xe8:calls.append(insn.operands[0].imm)
        if insn.mnemonic.startswith('ret'):break
    body=calls[-1];end=None
    for insn in cs.disasm(image[body:body+256],body):
        if insn.mnemonic.startswith('ret'):end=insn.address+insn.size;break
    assert end
    helper=image[body:end]
    return helper,{'external_executable_unique_match':True,'patch_bytes':bytes(p.replacement[:p.length]).hex(),'scan_seconds':round(elapsed,5)}

def main():
    helper,report=real_input();tested=0
    for regs in itertools.permutations([3,6,7]):
        for owner in [0,1,2]:
            for disp,near in [(0x44,False),(0x144,True)]:
                image,at,replacement,labels=fixture(helper,owner,*regs,array_disp=disp,near=near)
                n,p,actual=scan(image,[(0x1000,0x4000)])
                assert n==1 and actual==at and bytes(p.replacement[:p.length])==replacement,(regs,owner,disp,n,actual)
                image[at:at+len(replacement)]=replacement
                n,p,actual=scan(image,[(0x1000,0x4000)]);assert n==1 and p.already
                tested+=2
    image,at,replacement,labels=fixture(helper,wrapped=False,rva=0x1800)
    assert scan(image,[(0x1000,0x4000)])[0]==1;tested+=1
    base=fixture(helper)[0]
    # A duplicate must remain visible for the plugin's ambiguity check.
    second=fixture(helper,rva=0x1800)[0]
    base[0x1800:0x2000]=second[0x1800:0x2000]
    assert scan(base,[(0x1000,0x4000)])[0]==2;tested+=1
    for kind in ['flags','array_binding','branch','callee','truncated','partial_patch','capacity_store','decoy_return']:
        image,at,replacement,labels=fixture(helper)
        spans=[(0x1000,0x4000)]
        if kind=='flags':
            i=image.index(struct.pack('<I',0x400),labels['loop']);image[i]=1
        elif kind=='array_binding':image[0x1105]^=4
        elif kind=='branch':
            decoder=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
            jump=next(i for i in decoder.disasm(bytes(image[labels['loop']:]),labels['loop']) if i.mnemonic=='je')
            image[jump.address+jump.size-1]^=1
        elif kind=='callee':image[0x3000:0x3004]=b'\xc3\xcc\xcc\xcc'
        elif kind=='truncated':spans=[(0x1000,at-0x1000+3)]
        elif kind=='partial_patch':image[at:at+3]=replacement[:3]
        elif kind=='capacity_store':
            where=image.index(bytes.fromhex('897708'),0x2800,0x3000);image[where+2]=12
        elif kind=='decoy_return':image[0x2800]=0xc3
        assert scan(image,spans)[0]==0,kind
        tested+=1
    report['native_pattern_cases']=tested
    report['synthetic_variants']='register allocation, disp8/disp32 fields, short/near branches, moved functions, direct/wrapped calls, already-patched code, ambiguity, invalid/truncated contexts'
    (PROJECT/'native_validation.json').write_text(json.dumps(report,indent=2))
    (PROJECT/'helper_fixture.bin').write_bytes(helper)
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
