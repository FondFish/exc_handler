

#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ucontext.h>

# define REG_R8		0
# define REG_R9		1
# define REG_R10	2
# define REG_R11	3
# define REG_R12	4
# define REG_R13	5
# define REG_R14	6
# define REG_R15	7
# define REG_RDI	8
# define REG_RSI	9
# define REG_RBP	10
# define REG_RBX	11
# define REG_RDX	12
# define REG_RAX	13
# define REG_RCX	14
# define REG_RSP	15
# define REG_RIP	16
# define REG_EFL	17
# define REG_CSGSFS	18
# define REG_ERR	19
# define REG_TRAPNO	20
# define REG_OLDMASK	21
# define REG_CR2	22

typedef unsigned long   OSS_ULONG;
typedef char                CHAR;
typedef unsigned long   WORDPTR;
typedef int             INT;
typedef unsigned int       WORD32;
typedef unsigned short      WORD16;

#define   PRINT_WIDTH                2*sizeof(WORDPTR)
#define BTS_EXC_INFO_LEN    ((WORD32)(6*1024))  

static struct sigaction s_oact_segv; 

void EXC_SaveCtx(int signo, siginfo_t *info, void *context) 
{
    ucontext_t    *pContext = NULL;
    CHAR    *pucFirstFlag;
    WORDPTR eip, esp;
    INT     iIndex = 0;
    WORD32  dwBufUsedNum = 0;
    WORD16  wTmpSize;
    OSS_ULONG  dwCurrentSp, dwCpySize, dwPhyAddr;
    OSS_ULONG  *pCurrentSp;

    pContext = (ucontext_t*)context;


/*打印寄存器组*/

    esp = (WORDPTR)pContext->uc_mcontext.gregs[REG_RSP];
    eip = (WORDPTR)pContext->uc_mcontext.gregs[REG_RIP],

    /*打印寄存器*/
    printf( "----------------Exception Registers Start-----------------------\n");  

    printf( "RAX = 0x%0*lx  ", PRINT_WIDTH, (WORDPTR)pContext->uc_mcontext.gregs[REG_RAX]); 
    printf( "RBX = 0x%0*lx  ", PRINT_WIDTH, (WORDPTR)pContext->uc_mcontext.gregs[REG_RBX]);
    printf( "RCX = 0x%0*lx  ", PRINT_WIDTH, (WORDPTR)pContext->uc_mcontext.gregs[REG_RCX]);
    printf( "RDX = 0x%0*lx\n", PRINT_WIDTH, (WORDPTR)pContext->uc_mcontext.gregs[REG_RDX]); 

    printf( "RSI = 0x%0*lx  ", PRINT_WIDTH, (WORDPTR)pContext->uc_mcontext.gregs[REG_RSI]);
    printf( "RDI = 0x%0*lx  ", PRINT_WIDTH, (WORDPTR)pContext->uc_mcontext.gregs[REG_RDI]);
    printf( "RBP = 0x%0*lx  ", PRINT_WIDTH, (WORDPTR)pContext->uc_mcontext.gregs[REG_RBP]);
    printf( "RSP = 0x%0*lx\n", PRINT_WIDTH, (WORDPTR)pContext->uc_mcontext.gregs[REG_RSP]);

    printf( "R8  = 0x%0*lx  ", PRINT_WIDTH, (WORDPTR)pContext->uc_mcontext.gregs[REG_R8]);
    printf( "R9  = 0x%0*lx  ", PRINT_WIDTH, (WORDPTR)pContext->uc_mcontext.gregs[REG_R9]);
    printf( "R10 = 0x%0*lx  ", PRINT_WIDTH, (WORDPTR)pContext->uc_mcontext.gregs[REG_R10]);
    printf( "R11 = 0x%0*lx\n", PRINT_WIDTH, (WORDPTR)pContext->uc_mcontext.gregs[REG_R11]);

    printf( "R12 = 0x%0*lx  ", PRINT_WIDTH, (WORDPTR)pContext->uc_mcontext.gregs[REG_R12]);
    printf( "R13 = 0x%0*lx  ", PRINT_WIDTH, (WORDPTR)pContext->uc_mcontext.gregs[REG_R13]);
    printf( "R14 = 0x%0*lx  ", PRINT_WIDTH, (WORDPTR)pContext->uc_mcontext.gregs[REG_R14]);
    printf( "R15 = 0x%0*lx\n", PRINT_WIDTH, (WORDPTR)pContext->uc_mcontext.gregs[REG_R15]);

    printf("RIP: 0x%0-16lx  EFL: 0x%0-16lx CSGSFS: 0x%0-16lx  ERR: 0x%0-16lx\n",eip,pContext->uc_mcontext.gregs[REG_EFL],
        pContext->uc_mcontext.gregs[REG_CSGSFS],
        pContext->uc_mcontext.gregs[REG_ERR]);

    printf( "\n----------------Exception Registers End-------------------------\n\n");

    /*简单打印任务堆栈*/
    dwCurrentSp = (OSS_ULONG)esp;

    wTmpSize = BTS_EXC_INFO_LEN - dwBufUsedNum;

    dwCpySize = ((OSS_ULONG)esp & (~0xfff)) + 0x1000 - (OSS_ULONG)esp;
    dwCpySize = (dwCpySize < wTmpSize) ? dwCpySize : wTmpSize;
    pCurrentSp = (OSS_ULONG)dwCurrentSp;
    if((OSS_ULONG)pCurrentSp & 0x1)
    {
        printf("0x%lx: %016lx %016lx\n",pCurrentSp,*(pCurrentSp),*(pCurrentSp+1));
        pCurrentSp++;
    }
    for (iIndex = 0; iIndex < (INT)(dwCpySize / 16); iIndex++)
    {
         printf("0x%lx: %016lx %016lx\n",pCurrentSp,*(pCurrentSp),*(pCurrentSp+1));
        pCurrentSp = pCurrentSp + 2;                
    }
    /* 如果打印得太少，再打印1k */
    if ((dwCpySize < 100) && (dwCpySize < wTmpSize))
    {
        dwCpySize = 0x1000;
        for (iIndex = 0; iIndex < (INT)(dwCpySize / 16); iIndex++)
        {
            printf("0x%lx: %016lx %016lx\n",pCurrentSp,*(pCurrentSp),*(pCurrentSp+1)); 
            pCurrentSp = pCurrentSp + 2;                
        }
    }
}

void UnLoadSignal(int signo)
{
    sigaction(SIGSEGV,&s_oact_segv,NULL);
    raise(signo);
    return;
}
void SignalHandler(int signo, siginfo_t *info, void *context)
{    
    void *array[10];
    size_t size;
    char **strings;
    size_t i;
    
    ucontext_t    *pContext = NULL;
    pContext = (ucontext_t*)context;
      
    size = backtrace(array, 10);
    strings = backtrace_symbols(array, size);
    printf("Obtained %zd stack frames.\n", size);
    for (i = 0; i < size; i++)
        printf("%s\n", strings[i]);
    free(strings);
    
    printf("LinuxSignalHandler: Here comes an exception signal: %d, signal code: %d.\n",signo,info->si_code);
    
    printf("RIP: 0x%-16lx   RDI: 0x%-16lx   RBP: 0x%-16lx   RSP: 0x%-16lx\n",
            pContext->uc_mcontext.gregs[REG_RIP],
            pContext->uc_mcontext.gregs[REG_RDI],
            pContext->uc_mcontext.gregs[REG_RBP],
            pContext->uc_mcontext.gregs[REG_RSP]);

    EXC_SaveCtx(signo,info,context);
    UnLoadSignal(signo);
    exit(0);
}

void Test_Exc()
{
   int *testp=NULL;
   *testp=1;
}
void LoadSignal()
{
  struct sigaction act;
  
  memset(&act, 0, sizeof(act));
  
  act.sa_sigaction = SignalHandler;
  sigemptyset(&act.sa_mask);
  act.sa_flags = SA_SIGINFO|SA_ONSTACK;  
  sigaction(SIGSEGV,&act,&s_oact_segv);
}
void main()
{ 
    LoadSignal();
    Test_Exc();
    return;
}
