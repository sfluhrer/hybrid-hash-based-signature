#if !defined( LM_OTS_PARAM_H_ )
#define LM_OTS_PARAM_H_ 

/* The various W4 ("slow") parameter set settings */
#define LM_OTS_W4_PARAM_ID    0xe0000023
#define LM_OTS_W4_W                    4  /* Duh! */
#define LM_OTS_W4_P                   51  /* For n=192 */
#define LM_OTS_W4_LS                   4  /* For n=192 */

/* The various W2 ("fast") parameter set settings */
#define LM_OTS_W2_PARAM_ID    0xe0000022
#define LM_OTS_W2_W                    2  /* Duh! */
#define LM_OTS_W2_P                  101  /* For n=192 */
#define LM_OTS_W2_LS                   6  /* For n=192 */

#include "tune.h"

#if SPEED_SETTING

/* What to use as the signer */
#define LM_OTS_PARAM_ID   LM_OTS_W2_PARAM_ID
#define LM_OTS_W          LM_OTS_W2_W
#define LM_OTS_P          LM_OTS_W2_P
#define LM_OTS_LS         LM_OTS_W2_LS

#else

/* What to use as the signer */
#define LM_OTS_PARAM_ID   LM_OTS_W4_PARAM_ID
#define LM_OTS_W          LM_OTS_W4_W
#define LM_OTS_P          LM_OTS_W4_P
#define LM_OTS_LS         LM_OTS_W4_LS

#endif

#endif /* LM_OTS_PARAM_H_ */
