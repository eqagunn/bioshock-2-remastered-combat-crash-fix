#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "pattern.h"

static HMODULE g_module;
static HANDLE g_log=INVALID_HANDLE_VALUE;
static volatile LONG g_initialized;

static BOOL EqualBytes(const BYTE *a,const BYTE *b,SIZE_T size) {
    SIZE_T i;for(i=0;i<size;++i)if(a[i]!=b[i])return FALSE;return TRUE;
}
static DWORD TextLength(const char *s) {DWORD n=0;while(s[n])++n;return n;}
static void LogLine(const char *s) {
    DWORD written;
    if(g_log==INVALID_HANDLE_VALUE)return;
    WriteFile(g_log,s,TextLength(s),&written,NULL);WriteFile(g_log,"\r\n",2,&written,NULL);
}
static void LogLocation(DWORD rva,DWORD length) {
    char text[]="Detected patch: EXE +0x00000000, length 00 bytes.";
    const char hex[]="0123456789ABCDEF";
    DWORD i,start=TextLength("Detected patch: EXE +0x");
    for(i=0;i<8;++i)text[start+i]=hex[(rva>>(28-4*i))&15];
    start=TextLength("Detected patch: EXE +0x00000000, length ");
    text[start]=(char)('0'+length/10);text[start+1]=(char)('0'+length%10);
    LogLine(text);
}
static void OpenLog(void) {
    const WCHAR filename[]=L"Bioshock2HDCombatCrashFix.log";
    WCHAR path[MAX_PATH];DWORD n=GetModuleFileNameW(g_module,path,MAX_PATH),i,j;
    if(!n || n>=MAX_PATH)return;
    i=n;while(i && path[i-1]!=L'\\' && path[i-1]!=L'/')--i;
    if(i+sizeof(filename)/sizeof(filename[0])>MAX_PATH)return;
    for(j=0;j<sizeof(filename)/sizeof(filename[0]);++j)path[i+j]=filename[j];
    /* TRUNCATE_EXISTING never creates the opt-in log file. */
    g_log=CreateFileW(path,GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,TRUNCATE_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
}
static void CloseLog(void) {if(g_log!=INVALID_HANDLE_VALUE){CloseHandle(g_log);g_log=INVALID_HANDLE_VALUE;}}
static BOOL Readable(DWORD protection) {
    DWORD p=protection&0xff;
    return !(protection&(PAGE_GUARD|PAGE_NOACCESS)) &&
        (p==PAGE_READONLY || p==PAGE_READWRITE || p==PAGE_WRITECOPY ||
         p==PAGE_EXECUTE_READ || p==PAGE_EXECUTE_READWRITE || p==PAGE_EXECUTE_WRITECOPY);
}
static BOOL ReadableRange(const BYTE *p,SIZE_T size) {
    MEMORY_BASIC_INFORMATION m;
    ULONG_PTR start=(ULONG_PTR)p,limit=start+size,end;
    if(limit<start)return FALSE;
    while(start<limit) {
        if(VirtualQuery((LPCVOID)start,&m,sizeof(m))!=sizeof(m) || m.State!=MEM_COMMIT || !Readable(m.Protect))return FALSE;
        end=(ULONG_PTR)m.BaseAddress+m.RegionSize;
        if(end<=start)return FALSE;
        start=end;
    }
    return TRUE;
}
static BOOL BuildCodeSpans(BYTE *base) {
    IMAGE_DOS_HEADER *dos=(IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS32 *nt;
    IMAGE_SECTION_HEADER *sections;
    DWORD index,image_size,size,first_span;
    ULONG_PTR start,limit,end,image_end;
    MEMORY_BASIC_INFORMATION m;
    g_span_count=0;
    if(!ReadableRange(base,sizeof(*dos)) || dos->e_magic!=IMAGE_DOS_SIGNATURE || dos->e_lfanew<(LONG)sizeof(*dos))return FALSE;
    if((ULONG_PTR)base+(DWORD)dos->e_lfanew<(ULONG_PTR)base)return FALSE;
    nt=(IMAGE_NT_HEADERS32 *)(base+dos->e_lfanew);
    if(!ReadableRange((BYTE *)nt,sizeof(*nt)) || nt->Signature!=IMAGE_NT_SIGNATURE ||
       nt->FileHeader.Machine!=IMAGE_FILE_MACHINE_I386 || nt->OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
       nt->FileHeader.NumberOfSections==0 || nt->FileHeader.NumberOfSections>96 ||
       nt->FileHeader.SizeOfOptionalHeader<sizeof(IMAGE_OPTIONAL_HEADER32))return FALSE;
    image_size=nt->OptionalHeader.SizeOfImage;image_end=(ULONG_PTR)base+image_size;
    if(image_size<nt->OptionalHeader.SizeOfHeaders || image_end<=(ULONG_PTR)base)return FALSE;
    sections=IMAGE_FIRST_SECTION(nt);
    if((ULONG_PTR)sections<(ULONG_PTR)base || (ULONG_PTR)sections>image_end ||
       nt->FileHeader.NumberOfSections*sizeof(*sections)>image_end-(ULONG_PTR)sections ||
       !ReadableRange((BYTE *)sections,nt->FileHeader.NumberOfSections*sizeof(*sections)))return FALSE;
    for(index=0;index<nt->FileHeader.NumberOfSections;++index) {
        if(!(sections[index].Characteristics&IMAGE_SCN_MEM_EXECUTE))continue;
        size=sections[index].Misc.VirtualSize;
        if(!size)size=sections[index].SizeOfRawData;
        if(sections[index].VirtualAddress>=image_size || size>image_size-sections[index].VirtualAddress)return FALSE;
        start=(ULONG_PTR)base+sections[index].VirtualAddress;limit=start+size;
        first_span=g_span_count;
        while(start<limit) {
            if(VirtualQuery((LPCVOID)start,&m,sizeof(m))!=sizeof(m))return FALSE;
            end=(ULONG_PTR)m.BaseAddress+m.RegionSize;
            if(end<=start)return FALSE;
            if(end>limit)end=limit;
            if(m.State==MEM_COMMIT && Readable(m.Protect)) {
                if(g_span_count>first_span && g_spans[g_span_count-1].end==(const BYTE *)start) {
                    g_spans[g_span_count-1].end=(const BYTE *)end;
                } else {
                    if(g_span_count>=MAX_SPANS)return FALSE;
                    g_spans[g_span_count].begin=(const BYTE *)start;
                    g_spans[g_span_count].end=(const BYTE *)end;
                    ++g_span_count;
                }
            }
            start=end;
        }
    }
    return g_span_count!=0;
}
typedef struct {BYTE *start;SIZE_T size;DWORD protection;} Protection;
static BOOL RestoreCode(Protection *parts,DWORD count) {
    DWORD ignored;BOOL ok=TRUE;
    while(count) {--count;if(!VirtualProtect(parts[count].start,parts[count].size,parts[count].protection,&ignored))ok=FALSE;}
    return ok;
}
static BOOL UnlockCode(BYTE *start,DWORD size,Protection *parts,DWORD *count) {
    MEMORY_BASIC_INFORMATION m;BYTE *p=start,*end=start+size,*limit;
    *count=0;
    while(p<end) {
        if(*count>=4 || VirtualQuery(p,&m,sizeof(m))!=sizeof(m) || m.State!=MEM_COMMIT || !Readable(m.Protect)) {
            RestoreCode(parts,*count);return FALSE;
        }
        limit=(BYTE *)m.BaseAddress+m.RegionSize;
        if(limit<=p) {RestoreCode(parts,*count);return FALSE;}
        if(limit>end)limit=end;
        parts[*count].start=p;parts[*count].size=(SIZE_T)(limit-p);
        if(!VirtualProtect(p,(SIZE_T)(limit-p),PAGE_EXECUTE_READWRITE,&parts[*count].protection)) {
            RestoreCode(parts,*count);return FALSE;
        }
        ++*count;p=limit;
    }
    return TRUE;
}
static void ApplyPatch(void) {
    BYTE *base=(BYTE *)GetModuleHandleW(NULL);
    DWORD s,matches=0,protected_count,i;
    const BYTE *p;
    Patch candidate,selected;
    Protection protections[4];
    if(!base || !BuildCodeSpans(base)) {LogLine("REFUSED: executable memory could not be validated as readable x86 PE code.");return;}
    for(s=0;s<g_span_count;++s) {
        for(p=g_spans[s].begin;p<g_spans[s].end;++p) {
            if(*p!=0x8b || !TailPattern(p,&candidate))continue;
            if(matches && selected.site==candidate.site)continue;
            selected=candidate;
            if(++matches>1){LogLine("REFUSED: multiple validated actor-compaction patterns; no bytes were written.");return;}
        }
    }
    if(!matches) {LogLine("UNSUPPORTED: no validated actor-compaction pattern found; no bytes were written.");return;}
    LogLocation((DWORD)(selected.site-base),selected.length);
    if(selected.already){LogLine("ALREADY_PATCHED: matching no-shrink instructions are present; no write needed.");return;}
    if(!UnlockCode(selected.site,selected.length,protections,&protected_count)) {
        LogLine("REFUSED: VirtualProtect failed; no bytes were written.");return;
    }
    if(!EqualBytes(selected.site,selected.original,selected.length)) {
        RestoreCode(protections,protected_count);
        LogLine("REFUSED: matched instructions changed during initialization.");return;
    }
    for(i=0;i<selected.length;++i)((volatile BYTE *)selected.site)[i]=selected.replacement[i];
    if(!EqualBytes(selected.site,selected.replacement,selected.length) || !FlushInstructionCache(GetCurrentProcess(),selected.site,selected.length)) {
        for(i=0;i<selected.length;++i)((volatile BYTE *)selected.site)[i]=selected.original[i];
        FlushInstructionCache(GetCurrentProcess(),selected.site,selected.length);
        RestoreCode(protections,protected_count);
        LogLine("FAILED: write/cache verification failed; original instructions restored.");return;
    }
    if(!RestoreCode(protections,protected_count)) {
        LogLine("APPLIED_WITH_WARNING: patch active, but restoring code-page protection failed.");return;
    }
    LogLine("APPLIED: actor-array no-shrink patch verified (memory only).");
}
void __cdecl InitializeASI(void) {
    if(InterlockedCompareExchange(&g_initialized,1,0)!=0)return;
    OpenLog();LogLine("Bioshock 2 Remastered Combat Crash Fix by eqagunn - v1.0.0 (2026-10-25)");
    ApplyPatch();CloseLog();
}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,LPVOID reserved) {
    (void)reserved;
    if(reason==DLL_PROCESS_ATTACH){g_module=instance;DisableThreadLibraryCalls(instance);}
    return TRUE;
}
