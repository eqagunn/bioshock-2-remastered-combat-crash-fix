"""Run the compiled x86 DLL with mocked Win32 APIs and generated PE fixtures."""
import hashlib,json,struct,sys
from pathlib import Path
PROJECT=Path(__file__).resolve().parents[1]
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32,UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_PROT_READ,UC_PROT_WRITE,UC_PROT_EXEC
from unicorn.x86_const import *
from test_patterns import fixture

ASI=(PROJECT/'BioShock2HDCombatCrashFix.asi').read_bytes()
HELPER=(PROJECT/'helper_fixture.bin').read_bytes()
APIS={'DisableThreadLibraryCalls':1,'GetModuleHandleW':1,'GetModuleFileNameW':3,'CreateFileW':7,'WriteFile':5,'CloseHandle':1,'GetCurrentProcess':0,'VirtualProtect':4,'FlushInstructionCache':3,'VirtualQuery':3}

def release_metadata():
    dll=pefile.PE(data=ASI)
    fixed=dll.VS_FIXEDFILEINFO[0]
    assert (fixed.FileVersionMS,fixed.FileVersionLS)==(0x10000,0)
    assert (fixed.ProductVersionMS,fixed.ProductVersionLS)==(0x10000,0)
    assert fixed.FileType==2
    entries={}
    for info in dll.FileInfo:
        for item in info:
            if item.Key==b'StringFileInfo':
                for table in item.StringTable:entries.update({k.decode():v.decode() for k,v in table.entries.items()})
    expected={
        'CompanyName':'eqagunn','Author':'eqagunn',
        'FileDescription':'Bioshock 2 Remastered Combat Crash Fix',
        'ProductName':'Bioshock 2 Remastered Combat Crash Fix',
        'FileVersion':'1.0.0','ProductVersion':'1.0.0',
        'InternalName':'BioShock2HDCombatCrashFix',
        'OriginalFilename':'BioShock2HDCombatCrashFix.asi',
        'LegalCopyright':'Copyright (c) 2026 eqagunn. MIT License.',
        'Comments':'by eqagunn - v1.0.0 (2026-10-25)'
    }
    assert all(entries.get(k)==v for k,v in expected.items()),entries
    return expected

def make_pe(image,base):
    image[:0x1000]=bytes(0x1000);image[:2]=b'MZ';struct.pack_into('<I',image,0x3c,0x80)
    image[0x80:0x84]=b'PE\0\0';struct.pack_into('<HHIIIHH',image,0x84,0x14c,1,0x12345678,0,0,224,0x102)
    opt=0x98;struct.pack_into('<H',image,opt,0x10b);struct.pack_into('<I',image,opt+28,base)
    struct.pack_into('<II',image,opt+32,0x1000,0x200);struct.pack_into('<II',image,opt+56,len(image),0x1000)
    section=opt+224;image[section:section+8]=b'.text\0\0\0';struct.pack_into('<IIII',image,section+8,0x4000,0x1000,0x4000,0x1000);struct.pack_into('<I',image,section+36,0x60000020)

def run(case):
    asi_base=0x62000000 if case=='relocated' else 0x68000000
    exe_base=0x0fb00000 if case=='relocated' else 0x10900000
    options={}
    if case=='registers_fields':options=dict(owner=0,retained=3,scanreg=7,array=6,array_disp=0x144,flag_disp=0x234,near=True)
    if case=='direct_call':options['wrapped']=False
    image,at,replacement,labels=fixture(HELPER,**options)
    if case in ['cross_page','partial_protect_error']:
        offset=at-0x1100;image,at,replacement,labels=fixture(HELPER,rva=0x2000-offset-5)
        assert at==0x1ffb
    if case=='already_patched':image[at:at+len(replacement)]=replacement
    if case=='no_match':image[labels['loop']]=0x90
    if case=='partial_patch':image[at:at+3]=replacement[:3]
    if case=='ambiguous':
        second=fixture(HELPER,rva=0x1800)[0];image[0x1800:0x2000]=second[0x1800:0x2000]
    make_pe(image,exe_base)
    if case=='metadata':struct.pack_into('<I',image,0x88,0xfedcba98);struct.pack_into('<I',image,0x98+64,0x87654321)
    if case=='wrong_arch':struct.pack_into('<H',image,0x84,0x8664)
    if case=='invalid_sections':struct.pack_into('<H',image,0x86,97)
    initial=bytes(image);dll=pefile.PE(data=ASI);old_base=dll.OPTIONAL_HEADER.ImageBase
    assert dll.FILE_HEADER.Machine==0x14c and dll.FILE_HEADER.Characteristics&0x2000
    assert {m.dll.lower() for m in dll.DIRECTORY_ENTRY_IMPORT}=={b'kernel32.dll'}
    assert {e.name for e in dll.DIRECTORY_ENTRY_EXPORT.symbols}=={b'InitializeASI'}
    assert all(i.name!=b'OutputDebugStringA' for m in dll.DIRECTORY_ENTRY_IMPORT for i in m.imports)
    entry=dll.OPTIONAL_HEADER.AddressOfEntryPoint
    initialize=next(e.address for e in dll.DIRECTORY_ENTRY_EXPORT.symbols if e.name==b'InitializeASI')
    imports=[(i.address-old_base,i.name.decode()) for m in dll.DIRECTORY_ENTRY_IMPORT for i in m.imports]
    dll.relocate_image(asi_base);dll_image=dll.get_memory_mapped_image()
    u=Uc(UC_ARCH_X86,UC_MODE_32)
    u.mem_map(asi_base,(len(dll_image)+4095)&~4095);u.mem_write(asi_base,dll_image)
    u.mem_map(exe_base,len(image));u.mem_write(exe_base,initial)
    u.mem_map(0x40000000,0x10000);u.mem_map(0x50000000,0x10000)
    protections=[0x20]*6;protections[0]=2
    if case in ['cross_page','partial_protect_error']:protections[2]=0x80
    if case=='unreadable':protections[1:5]=[0x120]*4
    original_protections=protections.copy()
    calls=[];logs=bytearray();writes=[];protection_calls=[];cache=[];api_at={}
    def dw(a):return struct.unpack('<I',u.mem_read(a,4))[0]
    def wr(a,v):u.mem_write(a,struct.pack('<I',v&0xffffffff))
    def wide(a):
        b=bytearray()
        while True:
            x=bytes(u.mem_read(a,2));a+=2
            if x==b'\0\0':return b.decode('utf-16-le')
            b.extend(x)
    for index,(rva,name) in enumerate(imports):
        assert name in APIS,name
        address=0x50000000+index*16;api_at[address]=name;wr(asi_base+rva,address)
        u.mem_write(address,b'\xc2'+struct.pack('<H',4*APIS[name]) if APIS[name] else b'\xc3')
    def hook(uc,address,size,data):
        if address not in api_at:return
        name=api_at[address];sp=uc.reg_read(UC_X86_REG_ESP);a=[dw(sp+4+4*k) for k in range(APIS[name])];calls.append(name);result=1
        if name=='GetModuleHandleW':result=exe_base
        elif name=='GetModuleFileNameW':
            filename='RenamedPlugin.asi' if case=='log_renamed_plugin' else 'BioShock2HDCombatCrashFix.asi'
            path='C:\\Games\\Ž\\scripts\\'+filename;assert a[0]==asi_base and len(path)<a[2]
            uc.mem_write(a[1],path.encode('utf-16-le')+b'\0\0');result=len(path)
        elif name=='CreateFileW':
            assert wide(a[0])=='C:\\Games\\Ž\\scripts\\Bioshock2HDCombatCrashFix.log'
            assert a[1:]==[0x40000000,3,0,5,0x80,0],a
            result=0xffffffff if case in ['log_absent','log_unwritable'] else 0x100
        elif name=='WriteFile':assert a[0]==0x100;logs.extend(uc.mem_read(a[1],a[2]));wr(a[3],a[2])
        elif name=='GetCurrentProcess':result=0xffffffff
        elif name=='VirtualQuery':
            if not exe_base<=a[0]<exe_base+len(image):result=0
            else:
                page=(a[0]-exe_base)//4096;left=right=page
                while left and protections[left-1]==protections[page]:left-=1
                while right+1<len(protections) and protections[right+1]==protections[page]:right+=1
                uc.mem_write(a[1],struct.pack('<7I',exe_base+left*4096,exe_base,0x20,(right-left+1)*4096,0x1000,protections[page],0x1000000));result=28
        elif name=='VirtualProtect':
            protection_calls.append(tuple(a[:3]));start=(a[0]-exe_base)//4096;last=(a[0]+a[1]-1-exe_base)//4096
            assert 0<=start<=last<6
            wr(a[3],protections[start])
            unlocks=sum(p[2]==0x40 for p in protection_calls)
            if case=='protect_error' and len(protection_calls)==1:result=0
            elif case=='partial_protect_error' and a[2]==0x40 and unlocks==2:result=0
            elif case=='restore_error' and a[2]!=0x40:result=0
            else:
                for page in range(start,last+1):protections[page]=a[2]
                if case=='changed_during_init' and a[2]==0x40:uc.mem_write(exe_base+at,b'\xcc')
        elif name=='FlushInstructionCache':
            assert a==[0xffffffff,exe_base+at,len(replacement)];cache.append(a)
            if case=='cache_error' and len(cache)==1:result=0
        uc.reg_write(UC_X86_REG_EAX,result)
    def record(uc,access,address,size,value,data):
        if exe_base<=address<exe_base+len(image):writes.extend(range(address-exe_base,address-exe_base+size))
    u.hook_add(UC_HOOK_CODE,hook);u.hook_add(UC_HOOK_MEM_WRITE,record)
    def invoke(address,args):
        sp=0x4000f000;wr(sp,0x5000f000)
        for index,value in enumerate(args):wr(sp+4+4*index,value)
        u.reg_write(UC_X86_REG_ESP,sp);u.emu_start(address,0x5000f000,count=8000000)
        assert u.reg_read(UC_X86_REG_EIP)==0x5000f000,'instruction limit or invalid return'
        assert u.reg_read(UC_X86_REG_ESP)==sp+4+len(args)*4,'stack imbalance'
    invoke(asi_base+entry,[asi_base,1,0]);assert calls==['DisableThreadLibraryCalls'] and not writes
    invoke(asi_base+initialize,[]);log=bytes(logs).decode();expected=bytearray(initial)
    logging=case not in ['log_absent','log_unwritable']
    applied=case in ['normal','relocated','registers_fields','direct_call','metadata','cross_page','restore_error','log_absent','log_unwritable','log_renamed_plugin']
    if applied:expected[at:at+len(replacement)]=replacement
    if case=='changed_during_init':expected[at]=0xcc
    assert bytes(u.mem_read(exe_base,len(image)))==expected,(case,'unexpected memory change')
    if applied:
        assert len(writes)==len(replacement) and set(writes)==set(range(at,at+len(replacement)))
        if logging:assert 'APPLIED' in log and f'+0x{at:08X}' in log
    elif case=='already_patched':assert not writes and 'ALREADY_PATCHED' in log
    elif case=='cache_error':assert len(writes)==2*len(replacement) and 'FAILED' in log
    else:assert not writes and ('REFUSED' in log or 'UNSUPPORTED' in log)
    if case!='restore_error':assert protections==original_protections,(case,'protection not restored')
    if logging:
        assert log.startswith('Bioshock 2 Remastered Combat Crash Fix by eqagunn - v1.0.0 (2026-10-25)\r\n')
        assert calls.count('CloseHandle')==1
    else:assert not log and 'WriteFile' not in calls and 'CloseHandle' not in calls
    saved_calls=len(calls);saved_log=bytes(logs);invoke(asi_base+initialize,[])
    assert len(calls)==saved_calls and bytes(logs)==saved_log
    return {'case':case,'status':log.splitlines()[-1] if logging else 'APPLIED (logging disabled)','bytes_written':len(writes)}

def replacement_execution():
    checked=0
    for owner,retained,scanreg,array in [(0,3,6,7),(1,7,3,6),(2,6,7,3)]:
        for disp in [0x44,0x144]:
            image,at,code,_=fixture(HELPER,owner,retained,scanreg,array,array_disp=disp)
            u=Uc(UC_ARCH_X86,UC_MODE_32);u.mem_map(0x10000000,0x6000);u.mem_write(0x10000000,bytes(image));u.mem_write(0x10000000+at,code);u.mem_map(0x30000000,0x1000)
            u.mem_write(0x30000000,bytes([0x55])*0x1000)
            regs=[UC_X86_REG_EAX,UC_X86_REG_ECX,UC_X86_REG_EDX,UC_X86_REG_EBX,UC_X86_REG_ESP,UC_X86_REG_EBP,UC_X86_REG_ESI,UC_X86_REG_EDI]
            for r in regs:u.reg_write(r,0x88888888)
            u.reg_write(regs[owner],0x30000000);u.reg_write(regs[retained],123)
            before={r:u.reg_read(r) for r in regs};expected=bytearray(bytes([0x55])*0x1000);struct.pack_into('<I',expected,disp+4,123)
            u.emu_start(0x10000000+at,0x10000000+at+len(code),count=100)
            assert bytes(u.mem_read(0x30000000,0x1000))==expected
            assert before=={r:u.reg_read(r) for r in regs}
            checked+=1
    return checked

if __name__=='__main__':
    cases=['normal','relocated','registers_fields','direct_call','metadata','cross_page','already_patched','no_match','partial_patch','ambiguous','wrong_arch','invalid_sections','unreadable','protect_error','partial_protect_error','cache_error','restore_error','changed_during_init','log_absent','log_unwritable','log_renamed_plugin']
    results=[]
    for case in cases:
        r=run(case);results.append(r);print(json.dumps(r),flush=True)
    result={'compiled_binary_cases':results,'replacement_execution_cases':replacement_execution(),'versioninfo':release_metadata(),'asi_sha256':hashlib.sha256(ASI).hexdigest(),'test_environment':'Unicorn x86, mocked Win32 APIs; not a Windows or running-game test'}
    (PROJECT/'binary_validation.json').write_text(json.dumps(result,indent=2))
