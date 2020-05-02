#if !defined( LM_OTS_COMMON_H_ )
#define LM_OTS_COMMON_H_

unsigned lm_ots_compute_checksum(const unsigned char *Q, unsigned Q_len,
                                 unsigned w, unsigned ls);
unsigned lm_ots_coef(const unsigned char *Q, unsigned i, unsigned w);

#endif /* LM_OTS_COMMON_H_ */
