#define SYSCALLTEST 0

#define GADGET 0

/*********     Safe jump instruction switch   ********/
#define SAFE_INSTRUCTIONS 0
#define RJMP 0
#define MJMP 0

#define NO_OPTIMIZE_NOSAFEINST 0 /*No safe jump instruction, but removing one optimization*/
/*****************************************************/

/*********     stack   switch   ********/
#define SHADOW_STACK 0
#define TRA_SHADOW_STACK 0  /*First setting SHADOW_STACK = 1 then setting TRA = 1*/
#define NO2OPTIMIZE 0  /*First setting SHADOW_STACK = 1 then setting  = 1*/

#define NO_OPTIMIZE_NOSTACK 0  /*No stack, but removing one optimization, notice NO2OPTIMIZE_NOSTACK must be equal to 0*/
#define NO2OPTIMIZE_NOSTACK 0  /*No stack, but removing tow optimization, notice NO_OPTIMIZE_NOSTACK must be equal to 0*/
/***************************************/

#define PREVENT_UNINTEND 0

#define TBN 5


