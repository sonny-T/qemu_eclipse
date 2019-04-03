/*
 *  emulator main execution loop
 *
 *  Copyright (c) 2003-2005 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#include "qemu/osdep.h"
#include "cpu.h"
#include "trace.h"
#include "disas/disas.h"
#include "exec/exec-all.h"
#include "tcg.h"
#include "qemu/atomic.h"
#include "sysemu/qtest.h"
#include "qemu/timer.h"
#include "exec/address-spaces.h"
#include "qemu/rcu.h"
#include "exec/tb-hash.h"
#include "exec/log.h"
#if defined(TARGET_I386) && !defined(CONFIG_USER_ONLY)
#include "hw/i386/apic.h"
#endif
#include "sysemu/replay.h"

/* -icount align implementation. */

typedef struct SyncClocks {
    int64_t diff_clk;
    int64_t last_cpu_icount;
    int64_t realtime_clock;
} SyncClocks;

/* test cr3 VMI */
typedef struct{
	unsigned long pgd;
}pgd_t;
struct list_head{
	struct list_head *next,*prev;
};
struct mm_struct{
	unsigned long mm_nop[8];
	unsigned long pgd;
};
struct task_struct{
	unsigned long task_nop[99];
	struct list_head tasks;
	unsigned long task_nop1[8];
	unsigned long mm;
	unsigned long task_nop2[13];
	int pid;
};

/*** GRIN -M command options, MONITOR SYSCALL module ***/
//static int PCI = 0;
//static target_ulong TRACEPC_Buf[TBN];

static int GadgetLink = 0;

/************************************************/
/**  MOnitoring instruction ordinary variable  **/
/************************************************/

/* GRIN -M command options */
long dcount = 0;
unsigned long itotal = 0;
unsigned long jmp_total = 0;
unsigned long call_total = 0;
unsigned long ret_total = 0;

#if GADGET
long RealGadgetLen = 0;
#endif

/* GRIN TRA/SHADOW STACK module function */
ShadowStack sstack1;
int tsscount = 0;

/* GRIN VMI test*/
target_ulong cr3tmp = 0;
int _testbool = 0;

#if !defined(CONFIG_USER_ONLY)
/* Allow the guest to have a max 3ms advance.
 * The difference between the 2 clocks could therefore
 * oscillate around 0.
 */
#define VM_CLOCK_ADVANCE 3000000
#define THRESHOLD_REDUCE 1.5
#define MAX_DELAY_PRINT_RATE 2000000000LL
#define MAX_NB_PRINTS 100


static void align_clocks(SyncClocks *sc, const CPUState *cpu)
{
    int64_t cpu_icount;

    if (!icount_align_option) {
        return;
    }

    cpu_icount = cpu->icount_extra + cpu->icount_decr.u16.low;
    sc->diff_clk += cpu_icount_to_ns(sc->last_cpu_icount - cpu_icount);
    sc->last_cpu_icount = cpu_icount;

    if (sc->diff_clk > VM_CLOCK_ADVANCE) {
#ifndef _WIN32
        struct timespec sleep_delay, rem_delay;
        sleep_delay.tv_sec = sc->diff_clk / 1000000000LL;
        sleep_delay.tv_nsec = sc->diff_clk % 1000000000LL;
        if (nanosleep(&sleep_delay, &rem_delay) < 0) {
            sc->diff_clk = rem_delay.tv_sec * 1000000000LL + rem_delay.tv_nsec;
        } else {
            sc->diff_clk = 0;
        }
#else
        Sleep(sc->diff_clk / SCALE_MS);
        sc->diff_clk = 0;
#endif
    }
}

static void print_delay(const SyncClocks *sc)
{
    static float threshold_delay;
    static int64_t last_realtime_clock;
    static int nb_prints;

    if (icount_align_option &&
        sc->realtime_clock - last_realtime_clock >= MAX_DELAY_PRINT_RATE &&
        nb_prints < MAX_NB_PRINTS) {
        if ((-sc->diff_clk / (float)1000000000LL > threshold_delay) ||
            (-sc->diff_clk / (float)1000000000LL <
             (threshold_delay - THRESHOLD_REDUCE))) {
            threshold_delay = (-sc->diff_clk / 1000000000LL) + 1;
            printf("Warning: The guest is now late by %.1f to %.1f seconds\n",
                   threshold_delay - 1,
                   threshold_delay);
            nb_prints++;
            last_realtime_clock = sc->realtime_clock;
        }
    }
}

static void init_delay_params(SyncClocks *sc,
                              const CPUState *cpu)
{
    if (!icount_align_option) {
        return;
    }
    sc->realtime_clock = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL_RT);
    sc->diff_clk = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) - sc->realtime_clock;
    sc->last_cpu_icount = cpu->icount_extra + cpu->icount_decr.u16.low;
    if (sc->diff_clk < max_delay) {
        max_delay = sc->diff_clk;
    }
    if (sc->diff_clk > max_advance) {
        max_advance = sc->diff_clk;
    }

    /* Print every 2s max if the guest is late. We limit the number
       of printed messages to NB_PRINT_MAX(currently 100) */
    print_delay(sc);
}
#else
static void align_clocks(SyncClocks *sc, const CPUState *cpu)
{
}

static void init_delay_params(SyncClocks *sc, const CPUState *cpu)
{
}
#endif /* CONFIG USER ONLY */


/* GRIN function module
 * MONITOR JMP module */
static inline void grin_handle_jmp(target_ulong pc,target_ulong jmpaddr_of)
{
	FILE * pfile = NULL;
	char *token,*str1;
	char bufLine[30];
	char bufParser[2][20];
	target_ulong buf0,buf1;
	int i = 0;
	char c;

	if(coarsecfi_enabled || finecfi_enabled){
		if((pfile=fopen(jpath_buff,"r"))==NULL){
			printf("Read file failed!\n");
			printf("** File path should less than 100 bytes.\n"
					"** File path doesn't exist.\n");
			exit(0);
		}
	}
	while(coarsecfi_enabled || finecfi_enabled)
	{
		fgets(bufLine,30,pfile);
		for(i=0,str1=bufLine;i<2;i++,str1=NULL){
			if(bufLine[0] == '#'){
				goto nextline;
			}
			token = strtok(str1,"\t");
			strcpy(bufParser[i],token);
			//if(token==NULL){break;}
		}
		if(coarsecfi_enabled){
			//printf("%s---%s\n",bufParser[0],bufParser[1]);
			buf0 = strtol(bufParser[0],NULL,16);
			buf1 = strtol(bufParser[1],NULL,10);
			/* Coarse-grained CFI */
			if(pc==buf0){
				//printf("CFG have jmp to function head!\n");
				break;
			}
			if((pc>buf0)&&((jmpaddr_of-buf0)<buf1)&&((pc-buf0)<buf1))
			{/* Judge jmp dest is belong to function-self internal */
				//printf("CFG have jmp to function internal!\n");
				break;
			}
		}
		/* Fine-grained CFI */
//		buf0 = strtol(bufParser[0],NULL,16);
//		buf1 = strtol(bufParser[1],NULL,16);
//		if(jmpaddr_of==buf0){
//			printf("CFG have jmp to function head!\n");
//			if(pc!=buf1){
//				printf("JMP data wrong! dest: %lx s-target: %lx\n"
//						,pc,buf1);
//			}
//			break;
//		}
		c = getc(pfile);
		fseek(pfile,-1L,1);
		if(c=='\n'|| c==EOF){
			if(pc<0x4000000000){
				fprintf(stderr,"Dynamic execute result:\n"
							"Program is atttttttttacked _(:_l <)_\n");
				fprintf(stderr,"JMP, No match data in CFG! \n"
						"Dest: %lx \nSrc: %lx\n",pc,jmpaddr_of);
				exit(0);
			}
			break;
		}
nextline:
		continue;
	}
	if(coarsecfi_enabled || finecfi_enabled){
		fclose(pfile);
		if(dcount<=5 && jmpaddr_of<0x4000000000){
			fprintf(stderr,"\nGadget code icount: %d!\n",dcount);
			fprintf(stderr,"JMP ID: %d\ndest: %#lx \nsrc: %#lx\n",GadgetLink-1,pc,jmpaddr_of);
		}
		else
			GadgetLink = 0;
		/* Judge as gadget chain*/
		/* Don't consider libc's addr */
		if(GadgetLink == 6 && jmpaddr_of<0x4000000000){
			fprintf(stderr,"\nFormed a gadget chain!\n"
						"Program may be atttttttttacked!\n");
			GadgetLink = 0;
			exit(0);
		}
	}
	else{
#if !NOSTDERR
	fprintf(stderr,"JMP  d: %#lx  s: %#lx icount: %ld\n",
													pc,jmpaddr_of,dcount);
#endif
	}
    dcount = 0;
}
/* GRIN function module
 * MONITOR CALL module */
static inline  void grin_handle_call(target_ulong pc,
		target_ulong calladdr_of,target_ulong calladdr_next)
{
	FILE * pfile = NULL;
	char *token,*str1;
	char bufLine[100];
	char bufParser[2][20];
	target_ulong buf0,buf1;
	int i = 0;
	char c;
	if(coarsecfi_enabled || finecfi_enabled){
		if((pfile=fopen(cpath_buff,"r"))==NULL){
			printf("Read file failed!\n");
			printf("** File path should less than 100 bytes.\n"
					"** File path doesn't exist.\n");
			exit(0);
		}
	}
	while(coarsecfi_enabled || finecfi_enabled)
	{
		fgets(bufLine,30,pfile);
		for(i=0,str1=bufLine;i<2;i++,str1=NULL){
			if(bufLine[0] == '#'){
				goto nextline;
			}
			token = strtok(str1,"\t");
			strcpy(bufParser[i],token);
		}
		if(coarsecfi_enabled){
			//printf("%s---%s\n",bufParser[0],bufParser[1]);
			buf0 = strtol(bufParser[0],NULL,16);
			buf1 = strtol(bufParser[1],NULL,10);
			/* Coarse-grained CFI */
			if(pc==buf0){
				//printf("ret return to call next address!\n");
				break;
			}
		}
		/* Fine-grained CFI */
//		buf0 = strtol(bufParser[0],NULL,16);
//		buf1 = strtol(bufParser[1],NULL,16);
//		if(calladdr_of==buf0){
//			printf("CFG have call to function head!\n");
//			if(pc!=buf1){
//				printf("call data wrong! dest: %lx s-target: %lx src: %lx\n"
//						,pc,buf1,calladdr_of);
//			}
//			break;
//		}
		c = getc(pfile);
		fseek(pfile,-1L,1);
		if(c=='\n'|| c==EOF){
			if(pc<0x4000000000){
				fprintf(stderr,"Dynamic execute result:\n"
						"Program is atttttttttacked _(:_l <)_\n");
				fprintf(stderr,"CALL, No match data in CFG! \n Dest: %lx Src: %lx\n",pc,calladdr_of);
				exit(0);
			}
			break;
		}
nextline:
		continue;
	}

	if(coarsecfi_enabled || finecfi_enabled){
		fclose(pfile);
		if(dcount<=5 && calladdr_of<0x4000000000){
			fprintf(stderr,"\nGadget code icount: %d!\n",dcount);
			fprintf(stderr,"CALL ID: %d\ndest: %#lx \nsrc: %#lx beside addr: %#lx\n",
									GadgetLink-1,pc,calladdr_of,calladdr_next);
		}
		else
			GadgetLink = 0;
		/* Judge as gadget chain*/
		/* Don't consider libc's addr */
		if(GadgetLink == 6 && calladdr_of<0x4000000000){
			fprintf(stderr,"\nFormed a gadget chain!\n");
			fprintf(stderr,"Program may be atttttttttacked!\n");
			GadgetLink = 0;
			exit(0);
		}
	}
	else{
#if !NOSTDERR
	fprintf(stderr,"CALL d: %#lx  s: %#lx icount: %ld   beside addr: %#lx\n",
												pc,calladdr_of,dcount,calladdr_next);
#endif
	}
    dcount = 0;
}
/* GRIN function module
 * MONITOR RET module */
static inline void grin_handle_ret(target_ulong pc,target_ulong retaddr_of)
{
	FILE * pfile = NULL;
	char *token,*str1;
	char bufLine[100];
	char bufParser[2][20];
	target_ulong buf0,buf1;
	int i = 0;
	char c;

	if(coarsecfi_enabled || finecfi_enabled){
		if((pfile=fopen(rpath_buff,"r"))==NULL){
			printf("Read file failed!\n");
			printf("** File path should less than 100 bytes."
					"\n** File path doesn't exist.\n");
			exit(0);
		}
	}
	while(coarsecfi_enabled || finecfi_enabled)
	{
		fgets(bufLine,100,pfile);
		for(i=0,str1=bufLine;i<2;i++,str1=NULL){
			if(bufLine[0] == '#'){
				goto nextline;
			}
			token = strtok(str1,"\t");
			strcpy(bufParser[i],token);
		}
		if(coarsecfi_enabled){
			//printf("%s---%s\n",bufParser[0],bufParser[1]);
			/* Coarse-grained CFI */
			buf1 = strtol(bufParser[1],NULL,16);
			if(pc==buf1){
				//printf("ret return to call next address!\n");
				break;
			}
		}
		/* Fine-grained CFI */
//		buf0 = strtol(bufParser[0],NULL,16);
//		buf1 = strtol(bufParser[1],NULL,16);
//		if(retaddr_of==buf0){
//			printf("CFG have ret to function head! src: %lx\n"
//					,retaddr_of);
//			if(pc!=buf1){
//				printf("ret data wrong! dest: %lx s-target: %lx src: %lx\n"
//						,pc,buf1,retaddr_of);
//			}
//			break;
//		}
		c = getc(pfile);
		fseek(pfile,-1L,1);
		if(c=='\n'|| c==EOF){
			if(pc<0x4000000000){
				fprintf(stderr,"Dynamic execute result:\n"
						"Program is atttttttttacked _(:_l <)_\n");
				fprintf(stderr,"RET, No match data in CFG! \n Dest: %lx Src: %lx\n",pc,retaddr_of);
				exit(0);
			}
			break;
		}
nextline:
		continue;
	}

	if(coarsecfi_enabled || finecfi_enabled){
		//fclose(pfile);
		if(dcount<=5 && retaddr_of<0x4000000000){
			fprintf(stderr,"\nGadget code icount: %d!\n",dcount);
			fprintf(stderr,"RET ID: %d\n dest: %#lx \n src: %#lx \n",GadgetLink-1,pc,retaddr_of);
		}
		else
			GadgetLink = 0;
		/* Judge as gadget chain*/
		/* Don't consider libc's addr */
		if(GadgetLink == 7 && retaddr_of<0x4000000000){
			fprintf(stderr,"\nFormed a gadget chain!\n");
			fprintf(stderr,"Program may be atttttttttacked!\n");
			GadgetLink = 0;
			exit(0);
		}
	}
	else{
#if !NOSTDERR
	fprintf(stderr,"RET  d: %#lx  s: %#lx icount: %ld\n",
													pc,retaddr_of,dcount);
#endif
	}
    dcount = 0;
}

/* Execute a TB, and fix up the CPU state afterwards if necessary */
static inline tcg_target_ulong cpu_tb_exec(CPUState *cpu, TranslationBlock *itb)
{
    CPUArchState *env = cpu->env_ptr;
    uintptr_t ret;
    TranslationBlock *last_tb;
    int tb_exit;
    uint8_t *tb_ptr = itb->tc_ptr;

    /*  GRIN -ss/-tss command options
     *  TRA/SHADOW STACK module
     *  GRIN -M command options, MONITOR variable module */
    target_ulong pc_var;

    qemu_log_mask_and_addr(CPU_LOG_EXEC, itb->pc,
                           "Trace %p [" TARGET_FMT_lx "] %s\n",
                           itb->tc_ptr, itb->pc, lookup_symbol(itb->pc));

#if defined(DEBUG_DISAS)
    if (qemu_loglevel_mask(CPU_LOG_TB_CPU)) {
#if defined(TARGET_I386)
        log_cpu_state(cpu, CPU_DUMP_CCOP);
#elif defined(TARGET_M68K)
        /* ??? Should not modify env state for dumping.  */
        cpu_m68k_flush_flags(env, env->cc_op);
        env->cc_op = CC_OP_FLAGS;
        env->sr = (env->sr & 0xffe0) | env->cc_dest | (env->cc_x << 4);
        log_cpu_state(cpu, 0);
#else
        log_cpu_state(cpu, 0);
#endif
    }
#endif /* DEBUG_DISAS */

    cpu->can_do_io = !use_icount;
    ret = tcg_qemu_tb_exec(env, tb_ptr);
    cpu->can_do_io = 1;
    last_tb = (TranslationBlock *)(ret & ~TB_EXIT_MASK);
    tb_exit = ret & TB_EXIT_MASK;
    trace_exec_tb_exit(last_tb, tb_exit);

    if (tb_exit > TB_EXIT_IDX1) {
        /* We didn't start executing this TB (eg because the instruction
         * counter hit zero); we must restore the guest PC to the address
         * of the start of the TB.
         */
        CPUClass *cc = CPU_GET_CLASS(cpu);
        qemu_log_mask_and_addr(CPU_LOG_EXEC, last_tb->pc,
                               "Stopped execution of TB chain before %p ["
                               TARGET_FMT_lx "] %s\n",
                               last_tb->tc_ptr, last_tb->pc,
                               lookup_symbol(last_tb->pc));

        if (cc->synchronize_from_tb) {
            cc->synchronize_from_tb(cpu, last_tb);
        }
        else {
            assert(cc->set_pc);
            cc->set_pc(cpu, last_tb->pc);
        }
    }
    if (tb_exit == TB_EXIT_REQUESTED) {
        /* We were asked to stop executing TBs (probably a pending
         * interrupt. We've now stopped, so clear the flag.
         */
        cpu->tcg_exit_req = 0;
    }

    /*  GRIN -tss command options
     *  TRA STACK module function */
    if(grin_tra_shadowstack && itb->RETFlag){
    	pc_var = ShadowStackPop()-itb->cs_base;;
    	//printf("Pop stack---------------------------- %lx\n",pc_var);
		if(env->eip != pc_var){
#if !NOSTDERR
			fprintf(stderr,"TSS p: %#lx  s: %#lx\n"
					,env->eip,pc_var);
#endif
		}
       	tsscount--;
	fprintf(stderr,"Pop %d\n",tsscount);

    }
	/*  GRIN -ss command options
	 *  SHADOW STACK module */
    if(grin_shadowstack && itb->RETFlag){
    	if(env->eip != 0){
#if !NOSTDERR
    		fprintf(stderr,"Program is attacked!\n");
#endif
    	}
    	env->eip = ShadowStackPop();
    	//printf("Pop stack---------------------------- %lx\n",env->eip);
        }

    /* GRIN -M command options, MONITOR JMP module */
		//Mod67Flag is mod = 3
		//RMFlag is mod = 0 rm = 5
        if(grin_jmp){
        	//dcount += tb->icount;
			if(itb->JmpFlagM == 1){
				jmp_total += 1;
        		if(jmp_total>0x7fffffffffffffff){
        			printf("jmp overflow: %ld\n",jmp_total);
        			jmp_total = 0;
        		}
        		grin_handle_jmp(env->eip,itb->jmp_addr);
			}
        }

    /* GRIN -M command options, MONITOR CALL module */
        if (grin_call){
        	//dcount += tb->icount;
        	if(itb->CallFlagM == 1){
        		call_total += 1;
        		if(call_total>0x7fffffffffffffff){
        			printf("call overflow: %ld\n",call_total);
        			call_total = 0;
        		}
        		grin_handle_call(env->eip,itb->call_addr,itb->callnext_addr);
        	}
        }
        /* GRIN -M command options, MONITOR RET module */
        if (grin_ret){
        	//dcount += tb->icount;
        	if(itb->RetFlagM == 1){
            	ret_total += 1;
        		if(ret_total>0x7fffffffffffffff){
        			printf("ret overflow: %ld\n",ret_total);
        			ret_total = 0;
        		}
        		grin_handle_ret(env->eip,itb->ret_addr);
            }
        }
        if(grin_libfunc&&itb->JmpFlagM){
        	if((env->eip>0x4000000000)&&(itb->jmp_addr<0x4000000000)){
        			printf("caller: %lx  callee: %lx\n",itb->jmp_addr,env->eip);
        			printf("callee argement: %lx %lx %lx %lx\n",
        					env->regs[6],env->regs[7],env->regs[1],env->regs[2]);
        	}
        }

    return ret;
}

#ifndef CONFIG_USER_ONLY
/* Execute the code without caching the generated code. An interpreter
   could be used if available. */
static void cpu_exec_nocache(CPUState *cpu, int max_cycles,
                             TranslationBlock *orig_tb, bool ignore_icount)
{
    TranslationBlock *tb;
    bool old_tb_flushed;

    /* Should never happen.
       We only end up here when an existing TB is too long.  */
    if (max_cycles > CF_COUNT_MASK)
        max_cycles = CF_COUNT_MASK;

    old_tb_flushed = cpu->tb_flushed;
    cpu->tb_flushed = false;
    tb = tb_gen_code(cpu, orig_tb->pc, orig_tb->cs_base, orig_tb->flags,
                     max_cycles | CF_NOCACHE
                         | (ignore_icount ? CF_IGNORE_ICOUNT : 0));
    tb->orig_tb = cpu->tb_flushed ? NULL : orig_tb;
    cpu->tb_flushed |= old_tb_flushed;
    /* execute the generated code */
    trace_exec_tb_nocache(tb, tb->pc);
    cpu_tb_exec(cpu, tb);
    tb_phys_invalidate(tb, -1);
    tb_free(tb);
}
#endif

struct tb_desc {
    target_ulong pc;
    target_ulong cs_base;
    CPUArchState *env;
    tb_page_addr_t phys_page1;
    uint32_t flags;
};

static bool tb_cmp(const void *p, const void *d)
{
    const TranslationBlock *tb = p;
    const struct tb_desc *desc = d;

    if (tb->pc == desc->pc &&
        tb->page_addr[0] == desc->phys_page1 &&
        tb->cs_base == desc->cs_base &&
        tb->flags == desc->flags) {
        /* check next page if needed */
        if (tb->page_addr[1] == -1) {
            return true;
        } else {
            tb_page_addr_t phys_page2;
            target_ulong virt_page2;

            virt_page2 = (desc->pc & TARGET_PAGE_MASK) + TARGET_PAGE_SIZE;
            phys_page2 = get_page_addr_code(desc->env, virt_page2);
            if (tb->page_addr[1] == phys_page2) {
                return true;
            }
        }
    }
    return false;
}

static TranslationBlock *tb_find_physical(CPUState *cpu,
                                          target_ulong pc,
                                          target_ulong cs_base,
                                          uint32_t flags)
{
    tb_page_addr_t phys_pc;
    struct tb_desc desc;
    uint32_t h;

    desc.env = (CPUArchState *)cpu->env_ptr;
    desc.cs_base = cs_base;
    desc.flags = flags;
    desc.pc = pc;
    phys_pc = get_page_addr_code(desc.env, pc);
    desc.phys_page1 = phys_pc & TARGET_PAGE_MASK;
    h = tb_hash_func(phys_pc, pc, flags);
    return qht_lookup(&tcg_ctx.tb_ctx.htable, tb_cmp, &desc, h);
}

static TranslationBlock *tb_find_slow(CPUState *cpu,
                                      target_ulong pc,
                                      target_ulong cs_base,
                                      uint32_t flags)
{
    TranslationBlock *tb;

    tb = tb_find_physical(cpu, pc, cs_base, flags);
    if (tb) {
        goto found;
    }

#ifdef CONFIG_USER_ONLY
    /* mmap_lock is needed by tb_gen_code, and mmap_lock must be
     * taken outside tb_lock.  Since we're momentarily dropping
     * tb_lock, there's a chance that our desired tb has been
     * translated.
     */
    tb_unlock();
    mmap_lock();
    tb_lock();
    tb = tb_find_physical(cpu, pc, cs_base, flags);
    if (tb) {
        mmap_unlock();
        goto found;
    }
#endif

    /* if no translated code available, then translate it now */
    tb = tb_gen_code(cpu, pc, cs_base, flags, 0);

#ifdef CONFIG_USER_ONLY
    mmap_unlock();
#endif

found:
    /* we add the TB in the virtual pc hash table */
    cpu->tb_jmp_cache[tb_jmp_cache_hash_func(pc)] = tb;

    return tb;
}

/* GRIN TRA/SHADOW STACK module funciton */
void ShadowStackInit(void)
{
    ShadowStack *ss;
    ss = &sstack1;
	ss->top = 0;
	ss->MaxSize = 50;
	ss->stack = (target_ulong *)malloc(50*sizeof(target_ulong));
	if(!ss->stack){
		fprintf(stderr,"Shadow stack inital failed!\n");
	}
}

target_ulong ShadowStackPop(void)
{
	target_ulong x;
    ShadowStack *ss;
    ss = &sstack1;

	if(ss->top == 0){
		fprintf(stderr,"Pop shadow stack failed!\n");
		x = 0;
		return x;
	}
	x = ss->stack[ss->top];
	ss->top--;
	if(ss->top == 0){
		//free(ss->stack);
	}

	return x;
}

void ShadowStackPush(target_ulong x)
{
    ShadowStack *ss;
    ss = &sstack1;
	if(ss->top >= ss->MaxSize)
	{
		ss->stack = realloc(ss->stack,2*ss->MaxSize*sizeof(target_ulong));
		ss->MaxSize = 2*ss->MaxSize;
	}
	ss->top++;
	ss->stack[ss->top] = x;

}
/*********** end module ***********/

static inline TranslationBlock *tb_find_fast(CPUState *cpu,
                                             TranslationBlock **last_tb,
                                             int tb_exit)
{
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
    TranslationBlock *tb;
    target_ulong cs_base, pc;
    uint32_t flags;

    /* we record a subset of the CPU state. It will
       always be the same before a given translated block
       is executed. */
    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);

    /*** GRIN -encrypt command options, PRAR module ***/
    if(grin_prar){
    	if(pc == 0xffffffff){
    		fprintf(stderr,"The program is attacked!\n");
    		exit(1);
    	}
    }

    tb_lock();
    tb = cpu->tb_jmp_cache[tb_jmp_cache_hash_func(pc)];
    if (unlikely(!tb || tb->pc != pc || tb->cs_base != cs_base ||
                 tb->flags != flags)) {
        tb = tb_find_slow(cpu, pc, cs_base, flags);
    }
    if (cpu->tb_flushed) {
        /* Ensure that no TB jump will be modified as the
         * translation buffer has been flushed.
         */
        *last_tb = NULL;
        cpu->tb_flushed = false;
    }
#ifndef CONFIG_USER_ONLY
    /* We don't take care of direct jumps when address mapping changes in
     * system emulation. So it's not safe to make a direct jump to a TB
     * spanning two pages because the mapping for the second page can change.
     */
    if (tb->page_addr[1] != -1) {
        *last_tb = NULL;
    }
#endif
    /* See if we can patch the calling TB. */
    if (*last_tb && !qemu_loglevel_mask(CPU_LOG_TB_NOCHAIN)) {
    		//tb_add_jump(*last_tb, tb_exit, tb);
    }
    tb_unlock();
    /* GRIN -ss/-tss command options
     * TRA/SHADOW STACK module function */
    if(grin_shadowstack || grin_tra_shadowstack){
		if(tb->CALLFlag == 1){
			ShadowStackPush(tb->next_insn);
			//printf("Push stack****************************** %lx  next pc %lx\n"
			//		,tb->next_insn,env->tpush_reg);
			tsscount++;

			fprintf(stderr,"Push %d\n",tsscount);
		}
    }

    return tb;
}

static inline bool cpu_handle_halt(CPUState *cpu)
{
    if (cpu->halted) {
#if defined(TARGET_I386) && !defined(CONFIG_USER_ONLY)
        if ((cpu->interrupt_request & CPU_INTERRUPT_POLL)
            && replay_interrupt()) {
            X86CPU *x86_cpu = X86_CPU(cpu);
            apic_poll_irq(x86_cpu->apic_state);
            cpu_reset_interrupt(cpu, CPU_INTERRUPT_POLL);
        }
#endif
        if (!cpu_has_work(cpu)) {
            current_cpu = NULL;
            return true;
        }

        cpu->halted = 0;
    }

    return false;
}

static inline void cpu_handle_debug_exception(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    CPUWatchpoint *wp;

    if (!cpu->watchpoint_hit) {
        QTAILQ_FOREACH(wp, &cpu->watchpoints, entry) {
            wp->flags &= ~BP_WATCHPOINT_HIT;
        }
    }

    cc->debug_excp_handler(cpu);
}

static inline bool cpu_handle_exception(CPUState *cpu, int *ret)
{
    CPUArchState *env = cpu->env_ptr;


    if (cpu->exception_index >= 0) {
        if (cpu->exception_index >= EXCP_INTERRUPT) {
            /* exit request from the cpu execution loop */
            *ret = cpu->exception_index;
            if (*ret == EXCP_DEBUG) {
                cpu_handle_debug_exception(cpu);
            }
            cpu->exception_index = -1;
            return true;
        }
        else {
#if defined(CONFIG_USER_ONLY)
            /* if user mode only, we simulate a fake exception
               which will be handled outside the cpu execution
               loop */
#if defined(TARGET_I386)
            CPUClass *cc = CPU_GET_CLASS(cpu);
            cc->do_interrupt(cpu);
#endif
            *ret = cpu->exception_index;
            cpu->exception_index = -1;
            return true;
#else
            if (replay_exception()) {
                CPUClass *cc = CPU_GET_CLASS(cpu);
                rcu_read_lock();
                /* test cr3 VMI */
                /* cr3tmp compared last cr[3] value,
                 * if changed,to execute the following code.*/
                if((env->cr[3]>>12)^cr3tmp){
                    _testbool = 1;
                	cr3tmp = env->cr[3]>>12;
                }
                rcu_read_unlock();
                cc->do_interrupt(cpu);
                cpu->exception_index = -1;
            }
            else if (!replay_has_interrupt()) {
                /* give a chance to iothread in replay mode */
                *ret = EXCP_INTERRUPT;
                return true;
            }
#endif
        }
#ifndef CONFIG_USER_ONLY
    }
    else if (replay_has_exception()
               && cpu->icount_decr.u16.low + cpu->icount_extra == 0)
    {
        /* try to cause an exception pending in the log */
        TranslationBlock *last_tb = NULL; /* Avoid chaining TBs */
        cpu_exec_nocache(cpu, 1, tb_find_fast(cpu, &last_tb, 0), true);
        *ret = -1;
        return true;
#endif
    }

    return false;
}

static inline void cpu_handle_interrupt(CPUState *cpu,
                                        TranslationBlock **last_tb)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    int interrupt_request = cpu->interrupt_request;

    if (unlikely(interrupt_request)) {
        if (unlikely(cpu->singlestep_enabled & SSTEP_NOIRQ)) {
            /* Mask out external interrupts for this step. */
            interrupt_request &= ~CPU_INTERRUPT_SSTEP_MASK;
        }
        if (interrupt_request & CPU_INTERRUPT_DEBUG) {
            cpu->interrupt_request &= ~CPU_INTERRUPT_DEBUG;
            cpu->exception_index = EXCP_DEBUG;
            cpu_loop_exit(cpu);
        }
        if (replay_mode == REPLAY_MODE_PLAY && !replay_has_interrupt()) {
            /* Do nothing */
        }
        else if (interrupt_request & CPU_INTERRUPT_HALT) {
            replay_interrupt();
            cpu->interrupt_request &= ~CPU_INTERRUPT_HALT;
            cpu->halted = 1;
            cpu->exception_index = EXCP_HLT;
            cpu_loop_exit(cpu);
        }
#if defined(TARGET_I386)
        else if (interrupt_request & CPU_INTERRUPT_INIT) {
            X86CPU *x86_cpu = X86_CPU(cpu);
            CPUArchState *env = &x86_cpu->env;
            replay_interrupt();
            cpu_svm_check_intercept_param(env, SVM_EXIT_INIT, 0);
            do_cpu_init(x86_cpu);
            cpu->exception_index = EXCP_HALTED;
            cpu_loop_exit(cpu);
        }
#else
        else if (interrupt_request & CPU_INTERRUPT_RESET) {
            replay_interrupt();
            cpu_reset(cpu);
            cpu_loop_exit(cpu);
        }
#endif
        /* The target hook has 3 exit conditions:
           False when the interrupt isn't processed,
           True when it is, and we should restart on a new TB,
           and via longjmp via cpu_loop_exit.  */
        else {
            replay_interrupt();
            if (cc->cpu_exec_interrupt(cpu, interrupt_request)) {
                *last_tb = NULL;
            }
            /* The target hook may have updated the 'cpu->interrupt_request';
             * reload the 'interrupt_request' value */
            interrupt_request = cpu->interrupt_request;
        }
        if (interrupt_request & CPU_INTERRUPT_EXITTB) {
            cpu->interrupt_request &= ~CPU_INTERRUPT_EXITTB;
            /* ensure that no TB jump will be modified as
               the program flow was changed */
            *last_tb = NULL;
        }
    }
    if (unlikely(cpu->exit_request || replay_has_interrupt())) {
        cpu->exit_request = 0;
        cpu->exception_index = EXCP_INTERRUPT;
        cpu_loop_exit(cpu);
    }
}

static inline void cpu_loop_exec_tb(CPUState *cpu, TranslationBlock *tb,
                                    TranslationBlock **last_tb, int *tb_exit,
                                    SyncClocks *sc)
{
    uintptr_t ret;

    if (unlikely(cpu->exit_request)) {
        return;
    }

    trace_exec_tb(tb, tb->pc);
    ret = cpu_tb_exec(cpu, tb);

    *last_tb = (TranslationBlock *)(ret & ~TB_EXIT_MASK);

    *tb_exit = ret & TB_EXIT_MASK;
    switch (*tb_exit) {
    case TB_EXIT_REQUESTED:
        /* Something asked us to stop executing
         * chained TBs; just continue round the main
         * loop. Whatever requested the exit will also
         * have set something else (eg exit_request or
         * interrupt_request) which we will handle
         * next time around the loop.  But we need to
         * ensure the tcg_exit_req read in generated code
         * comes before the next read of cpu->exit_request
         * or cpu->interrupt_request.
         */
        smp_rmb();
        *last_tb = NULL;
        break;
    case TB_EXIT_ICOUNT_EXPIRED:
    {
        /* Instruction counter expired.  */
#ifdef CONFIG_USER_ONLY
        abort();
#else
        int insns_left = cpu->icount_decr.u32;
        if (cpu->icount_extra && insns_left >= 0) {
            /* Refill decrementer and continue execution.  */
            cpu->icount_extra += insns_left;
            insns_left = MIN(0xffff, cpu->icount_extra);
            cpu->icount_extra -= insns_left;
            cpu->icount_decr.u16.low = insns_left;
        } else {
            if (insns_left > 0) {
                /* Execute remaining instructions.  */
                cpu_exec_nocache(cpu, insns_left, *last_tb, false);
                align_clocks(sc, cpu);
            }
            cpu->exception_index = EXCP_INTERRUPT;
            *last_tb = NULL;
            cpu_loop_exit(cpu);
        }
        break;
#endif
    }
    default:
        break;
    }
}
/*** GRIN function module ***/
/** MONITOR SYSCALL module **/
/*static inline void grin_handle_syscall(TranslationBlock *tb,CPUState *cpu)
{
	target_ulong CURRPC;
	TranslationBlock *tb1;

	TRACEPC_Buf[PCI] = tb->pc;

    if(tb->syscall_flag == 1)
    {
    	for(int i = 0;i<TBN;i++)
    	{
    		CURRPC = TRACEPC_Buf[(PCI+i+1)%TBN];
    		tb1 = cpu->tb_jmp_cache[tb_jmp_cache_hash_func(CURRPC)];
    		printf("TB's first addr: %lx\n",tb1->pc);
    		for(uint16_t j = 0;j<(tb1->icount);j++)
    		{
    			printf("%s\n",tb1->t_code->tb_code[j]);
    		}
    	}
    	printf("\n");
    }
    PCI = PCI + 1;
    if(PCI == TBN)
    {
    	PCI = 0;
    }
} */

/* main execution loop */

int cpu_exec(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    int ret;
    SyncClocks sc;

    /* test cr3 VMI */
    CPUArchState *env = cpu->env_ptr;

    target_ulong *hva,*hva1,*hva2;
    target_ulong tmp;
    target_ulong tasks_prev = 0xffffffff81e17500+0x320;
    target_ulong init_task = 0xffffffff81e17500;

    struct task_struct *init_task1;
    struct mm_struct *mm1;
    struct list_head *list_head1;

    /* replay_interrupt may need current_cpu */
    current_cpu = cpu;

    if (cpu_handle_halt(cpu)) {
        return EXCP_HALTED;
    }

    atomic_mb_set(&tcg_current_cpu, cpu);
    rcu_read_lock();

    if (unlikely(atomic_mb_read(&exit_request))) {
        cpu->exit_request = 1;
    }

    cc->cpu_exec_enter(cpu);

    /* Calculate difference between guest clock and host clock.
     * This delay includes the delay of the last cycle, so
     * what we have to do is sleep until it is 0. As for the
     * advance/delay we gain here, we try to fix it next time.
     */
    init_delay_params(&sc, cpu);

    for(;;) {
        /* prepare setjmp context for exception handling */
        if (sigsetjmp(cpu->jmp_env, 0) == 0) {
            TranslationBlock *tb, *last_tb = NULL;
            int tb_exit = 0;
            /* if an exception is pending, we execute it here */
            if (cpu_handle_exception(cpu, &ret)) {
                break;
            }

            cpu->tb_flushed = false; /* reset before first TB lookup */
            for(;;)
            {
                cpu_handle_interrupt(cpu, &last_tb);
                tb = tb_find_fast(cpu, &last_tb, tb_exit);
                if(_testbool && (env->cr[2]>0x7fff00000000))
            	{
            		printf(" %lx\n",env->cr[3]>>12);
                	printf("ESP %lx EIP %lx CR2 %lx\n",
                			env->regs[4],env->eip,env->cr[2]);
                	/* test cr3 VMI */
                	/* init_task.tasks -> hva(init_task)+0x318
                	 * init_task.mm	   -> hva(init_task)+0x
                	 * next 0x318 prev 0x320*/

                	hva = get_hva(env, tasks_prev);
                	printf(" %lx\n",hva);
                	if(hva<0x7fffffffffff && hva>0x7f0000000000){
                		/* next */
                		tmp = *hva;
                		tmp = tmp - 0x318;
                		/* task_struct */
                		hva1 = get_hva(env, tmp);

                		//printf("next addr %016lx  %016lx\n\n",
                		//		init_task1->task_nop[99],
						//		init_task1->task_nop[100]);
                		if(hva1<0x7fffffffffff && hva1>0x7f0000000000){
                			init_task1 = (struct task_struct *)hva1;
							printf("mm %lx\n",init_task1->mm);
							if(init_task1->mm >0xff00000000000000){
							hva2 = get_hva(env, init_task1->mm);
							if(hva2<0x7fffffffffff && hva2>0x7f0000000000){
							mm1 = (struct mm_struct *)hva2;
							printf("pgd %lx\n",hva2);
							printf("pgd %lx\n\n",mm1->pgd);
							}
							}
							}
                	}
                	else
                		printf("@@@init_task %lx\n\n",hva);

                	_testbool = 0;
            	}

                /*temp test ltr*/
                if(tb->TestFlag)
                {
                	printf("new task %d\n",tb->TestFlag);
                }
                dcount += tb->icount;
                itotal += tb->icount;
        		if(grin_jmp&&(itotal>0x7fffffffffffffff)){
        			printf("The total number of instructions before clean:"
        							"total: %ld\n",itotal);
        			itotal = 0;
        		}
            /* GRIN -M command options, MONITOR SYSCALL module */
                if(grin_syscall){
                	if(tb->SyscallFlag){
                		//grin_handle_syscall(tb,cpu);
                		printf("system call !\n"
                				"address of syscall tb: %lx\n",tb->pc);
                	}
                }

                if(!(tb->RetFlagM||tb->CallFlagM||tb->JmpFlagM)){
                	if(dcount>=5){
                		GadgetLink = 0;
                	}
                }
                GadgetLink = (tb->RetFlagM || tb->CallFlagM || tb->JmpFlagM) + GadgetLink;
#if GADGET
                RealGadgetLen = RealGadgetLen + tb->icount;
                if(tb->IndirectFlag == 1)
                {
                	gadget_track(tb->IndirectDisas,RealGadgetLen);
                	RealGadgetLen = 0;
                	//printf("######%x\n",tb->IndirectDisas);
                }
#endif
                cpu_loop_exec_tb(cpu, tb, &last_tb, &tb_exit, &sc);

                if(grin_cc)
                {
//                	if(tb->pc == 0x400644){
//                		printf("t%d\n",tb->ccFlag);
//                	}
                	if(tb->ccFlag&&(tb->pc<0x4000000000)){
                		printf("operation number %d %lx\n",tb->SetccFlag,tb->pc);
                		printf("t0 %lx  t1 %lx\n",env->cc_t0,env->cc_t1);
                	}
                }
                /* Try to align the host and virtual clocks
                   if the guest is in advance */
                align_clocks(&sc, cpu);
            } /* for(;;) */
        } else {
#if defined(__clang__) || !QEMU_GNUC_PREREQ(4, 6)
            /* Some compilers wrongly smash all local variables after
             * siglongjmp. There were bug reports for gcc 4.5.0 and clang.
             * Reload essential local variables here for those compilers.
             * Newer versions of gcc would complain about this code (-Wclobbered). */
            cpu = current_cpu;
            cc = CPU_GET_CLASS(cpu);
#else /* buggy compiler */
            /* Assert that the compiler does not smash local variables. */
            g_assert(cpu == current_cpu);
            g_assert(cc == CPU_GET_CLASS(cpu));
#endif /* buggy compiler */
            cpu->can_do_io = 1;
            tb_lock_reset();
        }
    } /* for(;;) */

    cc->cpu_exec_exit(cpu);
    rcu_read_unlock();

    /* fail safe : never use current_cpu outside cpu_exec() */
    current_cpu = NULL;

    /* Does not need atomic_mb_set because a spurious wakeup is okay.  */
    atomic_set(&tcg_current_cpu, NULL);
    return ret;
}
