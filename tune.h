#if !defined(tune_h_)
#define TUNE_H_

/*
 * This file contains a series of tunable parameters that govern how this
 * package works.  The below comments try to explain what these parameters
 * do, and what the effect of changing them are.
 *
 * These parameters are independent, that is, any combination of settings
 * will work as expected.  There are some parameters which make sense to
 * coordinate; the comments will mention when that happens
 */

/*
 * This setting defines a trade-off between bulk signature speed, and
 * signature size.  It does not affect security.
 *
 * The 'fast' setting approximately doubles the rate which we can
 * generate signatures (of short messages, naturally), at the cost of
 * making each signature about 1k larger.  Fast also means that we use
 * more memory for our internal signature generation structure.
 *
 * It works by selecting the Winternitz parameter used within the LMS
 * signature; fast uses W=2, while slow uses W=4.  We also retune the
 * size of the Sphincs+ steps to account for the change.
 *
 * Also, surprisingly enough, adjusting this does not invalidate existing
 * private keys, public keys or signatures,  Any new signatures generated by
 * an existing private key will reflect the new setting; the verifier will
 * always accept both.
 */
#define SPEED_SETTING  1 /* 0 -> shrink the signature somewhat, at the */
                         /*      cost of not being able to generate them */
                         /*      quite as fast */
                         /* 1 -> make it faster to generate signatures, */
                         /*      at the cost of making them a bit bigger */

/*
 * This setting defines the algorithm that we use to convert our internal
 * secret keys into private LMS, Sphincs+ WOTS and FORS leafs.
 * We have two settings:
 * - We can use a SHA-256 based keygen algorithm.  It is slightly slower,
 *   however it means that we're not relying on a second crypto algorthm
 * - We can use an AES-based keygen algorithm.  It is a bit faster, but
 *   it also means that we're relying on the OpenSSL AES implementation
 * The speed difference (in terms of load time) would appear to be about
 * 1-2% in my tests (which used the OpenSSL version of SHA-256)
 *
 * Now, if you do change this setting, this invalidates any previous
 * private keys, as it changes the algortihm that translates the private
 * key seed into the FORS/Merkle private values.  Of course, it has no
 * effect on already generated signatures
 */
#define KEYGEN_STRATEGY 1 /* 0 -> we use a SHA-256 based keygen algorithm */
                          /*      (a bit slower, but we're not relying on */
                          /*      a second primtive) */
                          /* 1 -> we use an AES-based keygen algorithm */
                          /*      (slightly faster) */

/*
 * In eprint 2018/102, they have shown that a single fault in a hash
 * computation within Sphincs+ could potentially leak enough information to 
 * allow someone to forge signatures.
 *
 * This defines how we deal with this attack
 *
 * This attack is the observation is that WOTS+ signatures at the bottom of
 * the Merkle trees in the Sphincs+ hypertree sign values that are a
 * determanistic function of the hash evaluations of the previous level.
 * Hence, if we miscompute some hash somewhere in the previous level, we'll
 * sign the wrong item, violating the one-time-signature nature of WOTS+
 *
 * What this protection does is, for any hash that is used to determine what
 * a WOTS+ signature signs, we compute twice (typically at a higher level
 * than the individual hash functions), and compare.
 *
 * Note that there are some hash functions that aren't used to compute the
 * next value signed by WOTS+; we may not redundantly compute those.  A
 * miscomputation there may cause us to generate a signature that does not
 * validate; that's not something this protection is worried about.
 *
 * Costs of this protection:
 * - The load time approximately doubles (FAULT_STRATEGY 1) or quadruples
 *   (FAULT_STRATEGY 2)
 * - The memory consumed by a loaded private key increases somewhat (circa
 *   20k in my experience)
 * It does not increase the signature generation time (surprisingly enough)
 *
 * Changing this does not modify the signatures, nor does it invalidate any
 * generated public keys
 */
#define FAULT_STRATEGY 0 /* 0 -> we don't add any protection */
                       /* 1 -> we protect against failures; on a detected */
                       /*      failure, we go into an error state */
                       /* 2 -> we protect against failures; on a detected */
                       /*      failure, we attempt a recovery (by */
                       /*      rerunning the steps which came up with */
                       /*      inconsistent results). */

/*
 * This defines whether we use OpenSSL to compute SHA-256 hashes, or we use
 * our own implementation.
 *
 * Reasons to use OpenSSL: it's a *lot* faster (>2x in my tests, and that's
 * without the new-fangled SHA-256 instructions; if you do have those, I'd
 * expected the speed-up to be even more extreme).
 *
 * Reasons to use our own implementation: it has extra instrumentation that
 * counts the number of times you perform a hash compression operation,
 * which is useful during profiling.  Also, it's possible that there is some
 * platform that doesn't provide OpenSSL.
 *
 * Changing this does not effect the validity of any existing signatures or
 * public/private keys
 */
#define USE_OPENSSL 1   /* 0 -> Use our own instrumented SHA-256 */
                        /*      implementation */
                        /* 1 -> Use the OpenSSL implementation */

/*
 * We try to keep most of the step operations to be approximately equal cost
 * (so that we don't make some signatures unexpectedly expensive to generate)
 * Now, there are a few steps that are actually quite cheap (hence the
 * signatures generated during those steps will be unexpectedly quick).  This
 * determines wheether we add a dummy cost to try to even out those 
 * signatures a bit more.
 * If you're worred about the extra time this takes, well, this extra work is
 * disabled at load time.
 *
 * Changing this does not effect the validity of any existing signatures or
 * public/private keys
 */
#define DUMMY_LOAD 0   /* 0 -> no additional load is required, having a few */
                       /*      signature operations be a bit cheaper is not */
                       /*      an issue */
                       /* 1 -> add additional computations to those steps to */
                       /*      even things out more */

/*
 * These parameters below are here for testing purposes; you generally don't
 * need to modify them
 */

/*
 * While generating signatures, we incrementally build the next LMS tree and
 * sign it using the Sphincs+ private key.  One goal we have is not to make
 * any particular signature that expensive, and so we try to make each step
 * fairly cheap, and approximately equally expensive.
 *
 * There are a number of different types of operations ("steps"); the various
 * steps have been tuned to try to meet the goals of cheapness and equality,
 * we have this #define we can turn on as a test.
 *
 * If enabled, this prints out (at the end of the LMS tree/Sphincs+ signature
 * generation process, which happens while loading a key) the number of times
 * we ran each step, and the range of the expense of each step.  Viewing this,
 * we can see if we have tuned things properly.
 *
 * It counts 'expense' as 'number of times we've computed a SHA-256 hash
 * compression operation; because that's the major expense for each step,
 * that serves as a good guide.  However, in order for these stats to be
 * nonzero, we have to have USE_OPENSSL to be 0 (as the OpenSSL code is not
 * instrumented to update these stats).  In addition, for this test run,
 * you may want to set KEYGEN_STATEGY to be 0 (so that those are also counted
 * as part of the cost.  Also, during a profile run, you should have only one
 * thread calling this (because the internal profiling datastructures is kept
 * in global memory)
 *
 * Of course, this should be set only for test runs; for real applications,
 * this should always be 0
 *
 * Changing this does not effect the validity of any existing signatures or
 * public/private keys
 */
#define PROFILE           0  /* 1 -> Print out profile stats at the end of */
                             /*      a run */
                             /* 0 -> Be quiet */

/*
 * This determines whether we dump the initial Sphincs+ public key, signature
 * and LMS public key (the value signed by the public key) to a file
 * (sphincs-test.h); this happens on a key load
 * This is here so that we can periodically test whether our Sphincs+ code
 * is, in fact, correctly generating valid Sphincs+ signatures
 * This isn't a security issue; however there's no good reason this should
 * be on outside of a test
 */
#define DUMP_SIG 0     /* 0 -> don't dump them */
                       /* 1 -> do write them to a file */
 
#endif /* TUNE_H_ */
