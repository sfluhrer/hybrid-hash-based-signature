#include "param.h"


bool lookup_hypertree_geometry(int n, int fast, int *d, int *t) {
    int d_result, t_result;

#define HASH(n, fast) (2 * (n) + fast)
    switch (HASH(n, fast)) {
    case HASH(16, 0): d_result = 8; t_result = 8; break;
    case HASH(16, 1): d_result = 20; t_result = 3; break;
    case HASH(24, 0): d_result = 8; t_result = 8; break;
    case HASH(24, 1): d_result = 22; t_result = 3; break;
    case HASH(32, 0): d_result = 8; t_result = 8; break;
    case HASH(32, 1): d_result = 17; t_result = 4; break;
    default: return false;
    }
    if (d) *d = d_result;  /* Number of tree levels */
    if (t) *t = t_result;  /* Height of each tree */
    return true;
}
