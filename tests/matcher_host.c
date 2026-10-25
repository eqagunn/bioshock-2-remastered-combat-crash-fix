#include "pattern.h"
int remove_body_host(const BYTE *p){return RemoveBody(p);}
int scan_host(BYTE *memory,const DWORD *starts,const DWORD *sizes,DWORD spans,Patch *out) {
    DWORD n,count=0;const BYTE *p;Patch patch;
    if(spans>MAX_SPANS)return -1;
    g_span_count=spans;
    for(n=0;n<spans;++n){g_spans[n].begin=memory+starts[n];g_spans[n].end=memory+starts[n]+sizes[n];}
    for(n=0;n<spans;++n)for(p=g_spans[n].begin;p<g_spans[n].end;++p) {
        if(*p==0x8b && TailPattern(p,&patch)) {
            if(count && out->site==patch.site)continue;
            *out=patch;++count;
        }
    }
    return (int)count;
}
