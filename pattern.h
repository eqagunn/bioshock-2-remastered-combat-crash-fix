/* Constrained x86 semantic pattern matcher. No executable build profiles. */
#ifndef BS2_PATTERN_H
#define BS2_PATTERN_H
#include <windows.h>

#define MAX_PATCH 24
#define MAX_SPANS 128
typedef struct { const BYTE *begin,*end; } CodeSpan;
typedef struct {
    const BYTE *at,*next,*target;
    BYTE op,op2,reg,rm,mod,base,index,scale;
    LONG disp;
    DWORD imm;
    BOOL memory;
} Insn;
typedef struct {
    BYTE *site;
    BYTE original[MAX_PATCH],replacement[MAX_PATCH];
    DWORD length;
    BYTE owner,new_count;
    LONG count_offset;
    BOOL already;
} Patch;

static CodeSpan g_spans[MAX_SPANS];
static DWORD g_span_count;
static const BYTE *CodeEnd(const BYTE *p) {
    DWORD i;
    for(i=0;i<g_span_count;++i) if(p>=g_spans[i].begin && p<g_spans[i].end) return g_spans[i].end;
    return NULL;
}
static BOOL Available(const BYTE *p,SIZE_T n) {
    const BYTE *end=CodeEnd(p);
    return end && (SIZE_T)(end-p)>=n;
}
static DWORD U32(const BYTE *p) {
    return (DWORD)p[0]|((DWORD)p[1]<<8)|((DWORD)p[2]<<16)|((DWORD)p[3]<<24);
}
static BOOL ModRM(const BYTE **p,const BYTE *end,Insn *i) {
    BYTE m,s;
    if(*p>=end)return FALSE;
    m=*(*p)++;i->mod=m>>6;i->reg=(m>>3)&7;i->rm=m&7;
    i->memory=i->mod!=3;i->base=0xff;i->index=0xff;i->scale=0;i->disp=0;
    if(!i->memory)return TRUE;
    i->base=i->rm;
    if(i->rm==4) {
        if(*p>=end)return FALSE;
        s=*(*p)++;i->scale=s>>6;i->index=(s>>3)&7;i->base=s&7;
        if(i->index==4)i->index=0xff;
    }
    if(i->mod==0 && i->base==5) {
        i->base=0xff;
        if(end-*p<4)return FALSE;
        i->disp=(LONG)U32(*p);*p+=4;
    } else if(i->mod==1) {
        if(*p>=end)return FALSE;
        i->disp=(signed char)*(*p)++;
    } else if(i->mod==2) {
        if(end-*p<4)return FALSE;
        i->disp=(LONG)U32(*p);*p+=4;
    }
    return TRUE;
}
static BOOL Decode(const BYTE *at,Insn *i) {
    const BYTE *p=at,*end=CodeEnd(at);
    if(!end || p>=end)return FALSE;
    i->at=at;i->target=NULL;i->imm=0;i->op2=0;i->reg=0xff;
    i->rm=0xff;i->base=0xff;i->index=0xff;i->memory=FALSE;i->disp=0;i->mod=3;i->scale=0;
    i->op=*p++;
    switch(i->op) {
    case 0x8b:case 0x89:case 0x8d:case 0x3b:case 0x39:
    case 0x2b:case 0x29:case 0x85:case 0xff:
        if(!ModRM(&p,end,i))return FALSE;
        break;
    case 0xf7:case 0xc1:case 0x83:case 0x81:
        if(!ModRM(&p,end,i))return FALSE;
        if(i->op==0xf7 && i->reg!=0)return FALSE;
        if(i->op==0xf7 || i->op==0x81) {
            if(end-p<4)return FALSE;
            i->imm=U32(p);p+=4;
        } else {
            if(p>=end)return FALSE;
            i->imm=*p++;
        }
        break;
    case 0xe8:case 0xe9:
        if(end-p<4)return FALSE;
        i->disp=(LONG)U32(p);p+=4;i->target=p+i->disp;break;
    case 0x74:case 0x75:case 0x7c:case 0x7d:case 0x7f:case 0xeb:
        if(p>=end)return FALSE;
        i->disp=(signed char)*p++;i->target=p+i->disp;break;
    case 0x0f:
        if(p>=end)return FALSE;
        i->op2=*p++;
        if(i->op2!=0x84 && i->op2!=0x85 && i->op2!=0x8c && i->op2!=0x8d && i->op2!=0x8f)return FALSE;
        if(end-p<4)return FALSE;
        i->disp=(LONG)U32(p);p+=4;i->target=p+i->disp;break;
    case 0x6a:
        if(p>=end)return FALSE;
        i->imm=*p++;break;
    case 0x68:case 0x3d:
        if(end-p<4)return FALSE;
        i->imm=U32(p);p+=4;break;
    case 0xc2:
        if(end-p<2)return FALSE;
        i->imm=p[0]|((DWORD)p[1]<<8);p+=2;break;
    case 0xc3:case 0x90:break;
    default:
        if(i->op<0x40 || i->op>0x5f)return FALSE;
        break;
    }
    i->next=p;
    return p>at && p-at<=15;
}
static BOOL Step(const BYTE **p,Insn *i) {
    if(!Decode(*p,i))return FALSE;
    *p=i->next;return TRUE;
}
static BOOL Memory(const Insn *i,BYTE base,LONG disp) {
    return i->memory && i->base==base && i->index==0xff && i->disp==disp;
}
static BOOL Indexed(const Insn *i,BYTE base,BYTE index,LONG disp) {
    return i->memory && i->base==base && i->index==index && i->scale==2 && i->disp==disp;
}
static BOOL RegMove(const Insn *i,BYTE dest,BYTE src) {
    return !i->memory && ((i->op==0x8b && i->reg==dest && i->rm==src) ||
                               (i->op==0x89 && i->rm==dest && i->reg==src));
}
static BOOL Compare(const Insn *i,BYTE a,BYTE b) {
    return !i->memory && ((i->op==0x3b && i->reg==a && i->rm==b) ||
                               (i->op==0x39 && i->rm==a && i->reg==b));
}
static BOOL Subtract(const Insn *i,BYTE a,BYTE b) {
    return !i->memory && ((i->op==0x2b && i->reg==a && i->rm==b) ||
                               (i->op==0x29 && i->rm==a && i->reg==b));
}
static BOOL Jump(const Insn *i,BYTE cc) {
    return i->op==(BYTE)(0x70+cc) || (i->op==0x0f && i->op2==(BYTE)(0x80+cc));
}
static BOOL Increment(const Insn *i,BYTE reg) {
    return i->op==(BYTE)(0x40+reg) ||
        (i->op==0xff && !i->memory && i->reg==0 && i->rm==reg) ||
        (i->op==0x83 && !i->memory && i->reg==0 && i->rm==reg && i->imm==1);
}
static BOOL Epilogue(const BYTE *p) {
    Insn i;
    DWORD n=0;
    while(Decode(p,&i) && i.op>=0x58 && i.op<=0x5f && n<4) {p=i.next;++n;}
    if(!Decode(p,&i))return FALSE;
    if(RegMove(&i,4,5)) {
        p=i.next;
        if(!Step(&p,&i) || i.op!=0x5d)return FALSE;
    }
    if(!Decode(p,&i))return FALSE;
    return i.op==0xc3 || (i.op==0xc2 && i.imm==0);
}
static DWORD EncodeStore(BYTE *out,BYTE base,BYTE source,LONG disp) {
    DWORD n=0;
    BYTE mod;
    if(base==4)return 0;
    mod=(disp>=-128 && disp<=127)?1:2;
    out[n++]=0x89;out[n++]=(BYTE)((mod<<6)|(source<<3)|base);
    if(mod==1)out[n++]=(BYTE)disp;
    else {out[n++]=(BYTE)disp;out[n++]=(BYTE)(disp>>8);out[n++]=(BYTE)(disp>>16);out[n++]=(BYTE)(disp>>24);}
    return n;
}

/* Validate the complete compaction loop, including branches and index repair. */
static BOOL ActorLoop(const BYTE *start,const BYTE *tail,BYTE owner,BYTE retained,LONG count_disp,LONG array_disp) {
    const BYTE *p=start,*copy_label,*skip_label,*q;
    Insn i,j;
    BYTE array_reg,data_reg,actor,scan,copy_data,copy_actor;
    DWORD k;
    BOOL header_bound=FALSE;
    if(!Step(&p,&i) || i.op!=0x8b || !i.memory || i.base==0xff || i.index!=0xff || i.disp!=0)return FALSE;
    array_reg=i.base;data_reg=i.reg;
    if(!Step(&p,&i) || i.op!=0x8b || !i.memory || i.base!=data_reg || i.scale!=2 || i.index==0xff || i.disp!=0)return FALSE;
    actor=i.reg;scan=i.index;
    if(scan==retained || array_reg==scan || array_reg==retained || array_reg==owner || scan==4)return FALSE;
    if(!Step(&p,&i) || i.op!=0x85 || i.memory || i.reg!=actor || i.rm!=actor)return FALSE;
    if(!Step(&p,&i) || !Jump(&i,4))return FALSE;
    skip_label=i.target;
    if(!Step(&p,&i) || i.op!=0xf7 || !i.memory || i.base!=actor || i.index!=0xff || i.disp<0 || i.disp>0x10000 || i.imm!=0x400)return FALSE;
    if(!Step(&p,&i) || !Jump(&i,5) || i.target!=skip_label)return FALSE;
    if(!Step(&p,&i) || !Compare(&i,retained,scan))return FALSE;
    if(!Step(&p,&i) || !Jump(&i,4))return FALSE;
    copy_label=i.target;
    if(!Step(&p,&i) || i.op!=(BYTE)(0x50+retained))return FALSE;
    if(!Step(&p,&i) || !RegMove(&i,1,array_reg))return FALSE;
    if(!Step(&p,&i) || i.op!=0xe8 || !CodeEnd(i.target))return FALSE;
    if(p!=copy_label) {
        if(!Step(&p,&i) || i.op!=0x8b || i.reg!=owner || !i.memory ||
           (i.base!=4 && i.base!=5) || i.index!=0xff || i.disp<-0x1000 || i.disp>0x1000)return FALSE;
    }
    if(p!=copy_label)return FALSE;
    if(!Step(&p,&i) || i.op!=0x8b || !Memory(&i,array_reg,0))return FALSE;
    copy_data=i.reg;
    if(copy_data==retained || copy_data==scan || copy_data==owner)return FALSE;
    if(!Step(&p,&i) || !Increment(&i,retained))return FALSE;
    if(!Step(&p,&i) || i.op!=0x8b || !Indexed(&i,copy_data,scan,0))return FALSE;
    copy_actor=i.reg;
    if(!Step(&p,&i) || i.op!=0x89 || i.reg!=copy_actor || !Indexed(&i,copy_data,retained,-4))return FALSE;
    if(p!=skip_label || !Step(&p,&i) || !Increment(&i,scan))return FALSE;
    if(!Step(&p,&i) || i.op!=0x3b || i.reg!=scan || !Memory(&i,owner,count_disp))return FALSE;
    if(!Step(&p,&i) || !Jump(&i,12) || i.target!=start)return FALSE;
    if(p<tail && Decode(p,&i) && i.op==(BYTE)(0x58+array_reg))p=i.next;
    if(p!=tail)return FALSE;
    /* Tie the loop's array-header register to the owner and derived field. */
    for(k=2;k<=24;++k) {
        q=start-k;
        if(!Available(q,k))continue;
        if(Decode(q,&j) && j.op==0x8d && j.reg==array_reg && Memory(&j,owner,array_disp) &&
           j.next<=start && start-j.next<=8) {header_bound=TRUE;break;}
    }
    return header_bound;
}

/* Confirm the callee removes pointer-array elements and uses shrink/realloc.
   Calls may be direct or pass through a checked argument-forwarding wrapper. */
static BOOL RemoveBody(const BYTE *function) {
    const BYTE *p,*q,*after,*walk;
    Insn i,j,previous;
    DWORD n,k;
    BYTE array_reg,count_reg,new_num,old_max;
    BOOL shift=FALSE,capacity=FALSE,threshold=FALSE,realloc_store=FALSE,valid_prefix,returned;
    if(!Available(function,16))return FALSE;
    if(function[0]!=0x55 || function[1]!=0x8b || function[2]!=0xec)return FALSE;
    for(n=8;n<112;++n) {
        p=function+n;
        if(!Decode(p,&i) || i.op!=0x29 || !i.memory || i.index!=0xff || i.base==0xff || i.disp!=4)continue;
        array_reg=i.base;count_reg=i.reg;after=i.next;
        if(!Step(&after,&i) || i.op!=0x8b || !Memory(&i,array_reg,4))continue;
        new_num=i.reg;
        if(!Step(&after,&i) || i.op!=0x8b || !Memory(&i,array_reg,8))continue;
        old_max=i.reg;
        /* The immediately preceding call is a cdecl three-argument move. */
        for(k=5;k<=8;++k) {
            q=p-k;
            if(Decode(q,&j) && j.op==0xe8 && j.next==p && CodeEnd(j.target))break;
        }
        if(k>8)continue;
        shift=FALSE;capacity=FALSE;threshold=FALSE;realloc_store=FALSE;
        valid_prefix=TRUE;walk=function;
        while(walk<p) {
            if(!Step(&walk,&j) || walk>p || j.op==0xc2 || j.op==0xc3 || j.op==0xff ||
               (j.op==0xe8 && walk!=p) || (j.op==0x89 && j.memory) ||
               ((j.op==0x29 || j.op==0x2b) && j.memory)) {valid_prefix=FALSE;break;}
            if(j.op==0xc1 && !j.memory && j.reg==4 && j.imm==2)shift=TRUE;
            if(j.op==0x8b && j.reg==count_reg && Memory(&j,5,12))capacity=TRUE;
        }
        if(!valid_prefix || walk!=p)continue;
        /* Walk instruction boundaries and stop at the callee's own return. */
        walk=after;previous.op=0;previous.reg=0;previous.memory=FALSE;
        previous.index=0;previous.disp=0;returned=FALSE;
        while(walk-after<192) {
            if(!Step(&walk,&j))break;
            if(j.op==0xc2) {returned=j.imm==8;break;}
            if(j.op==0xc3)break;
            if((j.op==0x3d || (j.op==0x81 && j.reg==7)) && j.imm==0x4000)threshold=TRUE;
            if(j.op==0x89 && j.memory) {
                if(j.reg==0 && Memory(&j,array_reg,0) && previous.op==0xff && previous.reg==2 &&
                   previous.memory && previous.index==0xff && previous.disp==12)realloc_store=TRUE;
                else if(!(j.reg==new_num && Memory(&j,array_reg,8)) && j.base!=5)break;
            }
            previous=j;
        }
        (void)old_max;
        if(shift && capacity && threshold && realloc_store && returned)return TRUE;
    }
    return FALSE;
}
static BOOL RemovalCall(const BYTE *function) {
    DWORD n;
    const BYTE *p,*walk,*forward;
    Insn i;
    BOOL valid;
    BYTE saved;
    if(RemoveBody(function))return TRUE;
    if(!Available(function,3) || function[0]!=0x55 || function[1]!=0x8b || function[2]!=0xec)return FALSE;
    for(n=0;n<96;++n) {
        p=function+n;forward=p;walk=function;valid=TRUE;
        while(walk<forward) {
            if(!Step(&walk,&i) || walk>forward || i.op==0xc2 || i.op==0xc3) {valid=FALSE;break;}
        }
        if(!valid || walk!=forward)continue;
        if(!Step(&p,&i) || i.op!=0xff || i.reg!=6 || !Memory(&i,5,12))continue;
        if(!Step(&p,&i) || i.memory)continue;
        if(i.op==0x8b && i.reg==1)saved=i.rm;
        else if(i.op==0x89 && i.rm==1)saved=i.reg;
        else continue;
        if(!Step(&p,&i) || i.op!=0xff || i.reg!=6 || !Memory(&i,5,8))continue;
        if(!Step(&p,&i) || i.op!=0xe8 || !RemoveBody(i.target))continue;
        if(!Step(&p,&i) || i.op!=(BYTE)(0x58+saved))continue;
        if(!Step(&p,&i) || i.op!=0x5d)continue;
        if(!Step(&p,&i) || i.op!=0xc2 || i.imm!=8)continue;
        return TRUE;
    }
    return FALSE;
}

static BOOL TailPattern(const BYTE *tail,Patch *out) {
    const BYTE *p=tail,*end,*site,*remove=NULL,*loop;
    Insn i;
    BYTE owner,old_num,new_num,encoded[MAX_PATCH];
    LONG count_disp,array_disp;
    DWORD n,len,encoded_len,k;
    BOOL already=FALSE,loop_found=FALSE;
    if(!Step(&p,&i) || i.op!=0x8b || !i.memory || i.base==0xff || i.base==4 || i.index!=0xff)return FALSE;
    owner=i.base;old_num=i.reg;count_disp=i.disp;
    if(old_num==4 || owner==old_num || count_disp<4 || count_disp>0x10000)return FALSE;
    array_disp=count_disp-4;
    if(!Step(&p,&i) || i.memory)return FALSE;
    if(i.op==0x3b && i.rm==old_num)new_num=i.reg;
    else if(i.op==0x39 && i.reg==old_num)new_num=i.rm;
    else return FALSE;
    if(new_num==old_num || new_num==owner || new_num==4)return FALSE;
    if(!Step(&p,&i) || !Jump(&i,4))return FALSE;
    site=p;end=i.target;
    if(end<=site || end-site>MAX_PATCH || !Available(site,(SIZE_T)(end-site)) || !Epilogue(end))return FALSE;
    len=(DWORD)(end-site);
    encoded_len=EncodeStore(encoded,owner,new_num,count_disp);
    if(!encoded_len || encoded_len>len)return FALSE;
    if(Available(site,encoded_len)) {
        for(k=0;k<encoded_len && site[k]==encoded[k];++k){}
        if(k==encoded_len) {
            for(;k<len && site[k]==0x90;++k){}
            if(k==len)already=TRUE;
        }
    }
    if(!already) {
        if(!Step(&p,&i) || !Subtract(&i,old_num,new_num))return FALSE;
        if(!Step(&p,&i) || i.op!=(BYTE)(0x50+old_num))return FALSE;
        if(!Step(&p,&i) || i.op!=(BYTE)(0x50+new_num))return FALSE;
        if(!Step(&p,&i) || i.op!=0x8d || i.reg!=1 || !Memory(&i,owner,array_disp))return FALSE;
        if(!Step(&p,&i) || i.op!=0xe8 || p!=end)return FALSE;
        remove=i.target;
    }
    for(n=16;n<=224;++n) {
        loop=tail-n;
        if(CodeEnd(loop) && ActorLoop(loop,tail,owner,new_num,count_disp,array_disp)) {loop_found=TRUE;break;}
    }
    if(!loop_found || (!already && !RemovalCall(remove)))return FALSE;
    out->site=(BYTE *)site;out->length=len;out->already=already;
    out->owner=owner;out->new_count=new_num;out->count_offset=count_disp;
    for(k=0;k<len;++k) {out->original[k]=site[k];out->replacement[k]=(k<encoded_len)?encoded[k]:0x90;}
    return TRUE;
}
#endif
