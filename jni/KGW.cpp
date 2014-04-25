#include <inttypes.h>

#include <jni.h>
#include "mini-gmp.h"
#include <math.h>
#include <string.h>
#include <android/log.h>
typedef unsigned long uint64;
typedef long int64;

/*
First version of a native KGW implementation.  this version had byte[] inputs, but was using the uint256 type, which does not do division.

jbyteArray JNICALL calculatePastDifficultyAverage(JNIEnv * env, jint i, jbyteArray diff, jbyteArray past)
{
    jint dlen = (env)->GetArrayLength(diff);
    jbyte *d = (env)->GetByteArrayElements(diff, NULL);
    jint plen = (env)->GetArrayLength(diff);
    jbyte *p = (env)->GetByteArrayElements(diff, NULL);
      jbyteArray PastDifficultyAverage = (env)->NewByteArray(dlen);

    if(p && d)
    {
           if (i == 1)	{ //PastDifficultyAverage = d;
                        (env)->SetByteArrayRegion(PastDifficultyAverage, 0, dlen, d);
           }
            else
            {
                //PastDifficultyAverage = ((d.subtract(p)).divide(i).add(p));
                 uint256 ud(d, dlen);
                 uint256 up(p, plen);
                 uint256 ui(i);
                 uint256 pda = (ud - up);
                 pda = pda / ui;
                 pda = pda + up;

                 (env)->SetByteArrayRegion(PastDifficultyAverage, 0, pda.size(), (jbyte*)pda.begin());
            }
    }
    if (d) (env)->ReleaseByteArrayElements(diff, d, JNI_ABORT);
    if (p) (env)->ReleaseByteArrayElements(past, p, JNI_ABORT);

    return PastDifficultyAverage;
}*/

// Second version of a native KGW implementation.  This version had string inputs
/*
jstring JNICALL calculatePastDifficultyAverage2(JNIEnv * env, jint i, jstring diff, jstring past)
{
    jint dlen = (env)->GetStringLength(diff);
    const char *d = (env)->GetStringUTFChars(diff, JNI_FALSE);
    jint plen = (env)->GetStringLength(diff);
    const char *p = (env)->GetStringUTFChars(diff, JNI_FALSE);
    
	jstring PastDifficultyAverage = NULL;
	char result[64+1];

    if(p && d)
    {
         mpz_t D;
		 mpz_t P;
		 mpz_t R;
		 mpz_t I;
		 
		 mpz_init_set_str(D, (const char *)d, dlen);
		 mpz_init_set_str(P, (const char *)p, plen);
		 mpz_init_set_si(I, i);
		 mpz_init(R);
		 
		 
		 mpz_sub(R, D, P);
		 mpz_tdiv_q(R, R, I);
		 mpz_add(R, R, P);
		 
                
		
		mpz_get_str(result, 65, R);

        PastDifficultyAverage = (env)->NewStringUTF(result);
            
    }
    if (d) (env)->ReleaseStringUTFChars(diff, d);
    if (p) (env)->ReleaseStringUTFChars(past, p);

    return PastDifficultyAverage;
}
*/
/******** convert_j2mp() */
/*
 * Initializes the GMP value with enough preallocated size, and converts the
 * Java value into the GMP value. The value that mvalue points to should be
 * uninitialized
 */

void convert_j2mp(JNIEnv* env, jbyteArray jvalue, mpz_t* mvalue)
{
        jsize size;
        jbyte* jbuffer;
		//int sign;

        size = (env)->GetArrayLength(jvalue);
        jbuffer = (env)->GetByteArrayElements( jvalue, NULL);

        mpz_init2(*mvalue, sizeof(jbyte) * 8 * size); //preallocate the size

        /* void mpz_import(
         *   mpz_t rop, size_t count, int order, int size, int endian,
         *   size_t nails, const void *op);
         *
         * order = 1
         *   order can be 1 for most significant word first or -1 for least
         *   significant first.
         * endian = 1
         *   Within each word endian can be 1 for most significant byte first,
         *   -1 for least significant first.
         * nails = 0
         *   The most significant nails bits of each word are skipped, this can
         *   be 0 to use the full words.
         */
        mpz_import(*mvalue, size, 1, sizeof(jbyte), 1, 0, (void*)jbuffer);
		/*Uncomment this to support negative integer values,
		not tested though..
		sign = jbuffer[0] < 0?-1:1;
		if(sign == -1)
			mpz_neg(*mvalue,*mvalue);
		*/
        (env)->ReleaseByteArrayElements( jvalue, jbuffer, JNI_ABORT);
}

/******** convert_mp2j() */
/*
 * Converts the GMP value into the Java value; Doesn't do anything else.
 * Pads the resulting jbyte array with 0, so the twos complement value is always
 * positive.
 */

void convert_mp2j(JNIEnv* env, mpz_t mvalue, jbyteArray* jvalue)
{
        jsize size;
        jbyte* buffer;
        jboolean copy;
		//int i;

        copy = JNI_FALSE;

        /* sizeinbase() + 7 => Ceil division */
        size = (mpz_sizeinbase(mvalue, 2) + 7) / 8 + sizeof(jbyte);
        *jvalue = (env)->NewByteArray(size);

        buffer = (env)->GetByteArrayElements(*jvalue, &copy);
        buffer[0] = 0x00;
		//Uncomment the comments below to support negative integer values,
		//not very well-tested though..
		//if(mpz_sgn(mvalue) >=0){
		mpz_export((void*)&buffer[1], (size_t*)&size, 1, sizeof(jbyte), 1, 0, mvalue);
		//}else{
		//	mpz_add_ui(mvalue,mvalue,1);
		//	mpz_export((void*)&buffer[1], &size, 1, sizeof(jbyte), 1, 0, mvalue);
		//	for(i =0;i<=size;i++){ //This could be done more effectively
		//		buffer[i]=~buffer[i];
		//	}
		//}

		/* mode has (supposedly) no effect if elems is not a copy of the
         * elements in array
         */
        (env)->ReleaseByteArrayElements(*jvalue, buffer, 0);
        //mode has (supposedly) no effect if elems is not a copy of the elements in array
}

jbyteArray JNICALL cpda(JNIEnv * env, jclass cls, jint i, jbyteArray diff, jbyteArray past)
{
    __android_log_print(ANDROID_LOG_INFO, "cpda", "Initializing with %d, %016x, %016x...", i, diff, past);
    jint dlen = (env)->GetArrayLength(diff);
    __android_log_print(ANDROID_LOG_INFO, "cpda", "Diff array len = %d", dlen);
    jbyte *d = (env)->GetByteArrayElements(diff, NULL);
    __android_log_print(ANDROID_LOG_INFO, "cpda", "Diff array ptr = %016x", d);
    jint plen = (env)->GetArrayLength(past);
    __android_log_print(ANDROID_LOG_INFO, "cpda", "Past array len = %d", plen);
    jbyte *p = (env)->GetByteArrayElements(past, NULL);
    __android_log_print(ANDROID_LOG_INFO, "cpda", "Past array ptr = %016x", p);

	jbyteArray PastDifficultyAverage = NULL;
	//char result[64+1];
    __android_log_write(ANDROID_LOG_INFO, "cpda", "Initializing Complete.");
    if(p && d)
    {
         mpz_t D;
		 mpz_t P;
		 mpz_t R;
		 mpz_t I;
		 
		 char s[129];

		 //mpz_init(D);//, (const char *)d, dlen);
		 //mpz_import(D, 32, 1, 1, 0, 0, (const char*)d);
		 convert_j2mp(env, diff, &D);
		 mpz_get_str(s, 10, D);
		 __android_log_print(ANDROID_LOG_INFO, "cpda", "diff number is = %s", s);
		 //mpz_init(P);//, (const char *)p, plen);
		 //mpz_import(P, 32, 1, 1, 0, 0, (const char*)p);
		 convert_j2mp(env, past, &P);
		 mpz_init_set_si(I, i);
		 mpz_init(R);


		 mpz_sub(R, D, P);
		 mpz_tdiv_q(R, R, I);
		 mpz_add(R, R, P);


        //PastDifficultyAverage = (env)->NewByteArray(32);
        convert_mp2j(env, R, &PastDifficultyAverage);/*(env)->NewByteArray(32);
        jbyte *pda = (env)->GetByteArrayElements(PastDifficultyAverage, NULL);
        size_t size = 0;
		mpz_export(pda, &size, 1, 1, 1, 0, R);
		env->ReleaseByteArrayElements(PastDifficultyAverage, pda, JNI_ABORT);*/


        //env->SetByteArrayRegion(DK, 0, 32, (jbyte *) result.begin())

    }
    if (d) (env)->ReleaseByteArrayElements(diff, d, JNI_ABORT);
    if (p) (env)->ReleaseByteArrayElements(past, p, JNI_ABORT);

    return PastDifficultyAverage;
}


/*jbyteArray JNICALL hash9_native(JNIEnv *env, jclass cls, jbyteArray header)
{
    jint Plen = (env)->GetArrayLength(header);
    jbyte *P = (env)->GetByteArrayElements(header, NULL);
    //uint8_t *buf = malloc(sizeof(uint8_t) * dkLen);
    jbyteArray DK = NULL;

    if (P)
	{

	uint256 result = Hash9(P, P+Plen);



    DK = (env)->NewByteArray(32);
    if (DK)
	{
		(env)->SetByteArrayRegion(DK, 0, 32, (jbyte *) result.begin());
	}


    if (P) (env)->ReleaseByteArrayElements(header, P, JNI_ABORT);
    //if (buf) free(buf);
	}
    return DK;
}*/

/*
unsigned int static KimotoGravityWell(const CBlockIndex* pindexLast, const CBlockHeader *pblock, uint64 TargetBlocksSpacingSeconds, uint64 PastBlocksMin, uint64 PastBlocksMax) {

	const CBlockIndex  *BlockLastSolved				= pindexLast;
	const CBlockIndex  *BlockReading				= pindexLast;
	const CBlockHeader *BlockCreating				= pblock;
						BlockCreating				= BlockCreating;
	uint64				PastBlocksMass				= 0;
	int64				PastRateActualSeconds		= 0;
	int64				PastRateTargetSeconds		= 0;
	double				PastRateAdjustmentRatio		= double(1);
	CBigNum				PastDifficultyAverage;
	CBigNum				PastDifficultyAveragePrev;
	double				EventHorizonDeviation;
	double				EventHorizonDeviationFast;
	double				EventHorizonDeviationSlow;

    if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || (uint64)BlockLastSolved->nHeight < PastBlocksMin) { return bnProofOfWorkLimit.GetCompact(); }

	for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
		if (PastBlocksMax > 0 && i > PastBlocksMax) { break; }
		PastBlocksMass++;

		if (i == 1)	{ PastDifficultyAverage.SetCompact(BlockReading->nBits); }
		else		{ PastDifficultyAverage = ((CBigNum().SetCompact(BlockReading->nBits) - PastDifficultyAveragePrev) / i) + PastDifficultyAveragePrev; }
		PastDifficultyAveragePrev = PastDifficultyAverage;

		PastRateActualSeconds			= BlockLastSolved->GetBlockTime() - BlockReading->GetBlockTime();
		PastRateTargetSeconds			= TargetBlocksSpacingSeconds * PastBlocksMass;
		PastRateAdjustmentRatio			= double(1);
		if (PastRateActualSeconds < 0) { PastRateActualSeconds = 0; }
		if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
		PastRateAdjustmentRatio			= double(PastRateTargetSeconds) / double(PastRateActualSeconds);
		}
		EventHorizonDeviation			= 1 + (0.7084 * pow((double(PastBlocksMass)/double(144)), -1.228));
		EventHorizonDeviationFast		= EventHorizonDeviation;
		EventHorizonDeviationSlow		= 1 / EventHorizonDeviation;

		if (PastBlocksMass >= PastBlocksMin) {
			if ((PastRateAdjustmentRatio <= EventHorizonDeviationSlow) || (PastRateAdjustmentRatio >= EventHorizonDeviationFast)) { assert(BlockReading); break; }
		}
		if (BlockReading->pprev == NULL) { assert(BlockReading); break; }
		BlockReading = BlockReading->pprev;
	}

	CBigNum bnNew(PastDifficultyAverage);
	if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
		bnNew *= PastRateActualSeconds;
		bnNew /= PastRateTargetSeconds;
	}
    if (bnNew > bnProofOfWorkLimit) { bnNew = bnProofOfWorkLimit; }

    /// debug print
    printf("Difficulty Retarget - Kimoto Gravity Well\n");
    printf("PastRateAdjustmentRatio = %g\n", PastRateAdjustmentRatio);
    printf("Before: %08x  %s\n", BlockLastSolved->nBits, CBigNum().SetCompact(BlockLastSolved->nBits).getuint256().ToString().c_str());
    printf("After:  %08x  %s\n", bnNew.GetCompact(), bnNew.getuint256().ToString().c_str());

	return bnNew.GetCompact();
} */

//
// This is the current implimentation of the KimotoGravityWell, which assumes that only one thread will call this function at a time.
//
//  Many parameters are stored as global variables.  they are initialized when KimotoGravityWell_init is called.
//

	uint64				PastBlocksMass				= 0;
	int64				PastRateActualSeconds		= 0;
	int64				PastRateTargetSeconds		= 0;
	double				PastRateAdjustmentRatio		= double(1);
	mpz_t				PastDifficultyAverage;
	mpz_t				PastDifficultyAveragePrev;
	double				EventHorizonDeviation;
	double				EventHorizonDeviationFast;
	double				EventHorizonDeviationSlow;
	double              DeviationDenominator;
	mpz_t               CurrentIteration;
	mpz_t               CurrentDifficulty;
    uint64 TargetBlocksSpacingSeconds;
    uint64 PastBlocksMin;
    uint64 PastBlocksMax;
enum KGW_results {
    PROOF_OF_WORK_LIMIT = -2,

    CONTINUE = 0,
    STOP = 1,
    EXIT = 2,

};
//
// Initializes global variables above. ^^^
//

int KimotoGravityWell_init(JNIEnv * env, jclass cls,jlong _TargetBlocksSpacingSeconds, jlong _PastBlocksMin, jlong _PastBlocksMax, double _DeviationDenominator)
{
    PastBlocksMass				= 0;
    PastRateActualSeconds		= 0;
    PastRateTargetSeconds		= 0;
    PastRateAdjustmentRatio		= double(1);

	TargetBlocksSpacingSeconds = _TargetBlocksSpacingSeconds;
	PastBlocksMin = _PastBlocksMin;
	PastBlocksMax = _PastBlocksMax;
	DeviationDenominator = _DeviationDenominator;

	mpz_init(PastDifficultyAverage);
	mpz_init(PastDifficultyAveragePrev);
	mpz_init(CurrentIteration);
    mpz_init(CurrentDifficulty);

	return CONTINUE;
}
    unsigned int readUint32BE(char * bytes, int offset) {
        return ((bytes[offset + 0] & 0xFFL) << 24) |
                ((bytes[offset + 1] & 0xFFL) << 16) |
                ((bytes[offset + 2] & 0xFFL) << 8) |
                ((bytes[offset + 3] & 0xFFL) << 0);
    }
        unsigned int readUint32(char * bytes, int offset) {
            return ((bytes[offset++] & 0xFFL) << 0) |
                    ((bytes[offset++] & 0xFFL) << 8) |
                    ((bytes[offset++] & 0xFFL) << 16) |
                    ((bytes[offset] & 0xFFL) << 24);
        }

    void bin_to_strhex(unsigned char *bin, unsigned int binsz, char **result)
    {
      char          hex_str[]= "0123456789abcdef";
      unsigned int  i;

      *result = (char *)malloc(binsz * 2 + 1);
      (*result)[binsz * 2] = 0;

      if (!binsz)
        return;

      for (i = 0; i < binsz; i++)
        {
          (*result)[i * 2 + 0] = hex_str[bin[i] >> 4  ];
          (*result)[i * 2 + 1] = hex_str[bin[i] & 0x0F];
        }
    }

    //the calling
    void print_array(char * buf, int size, char * message)
    {
        //char buf[] = {0,1,10,11};
        char *result;

        bin_to_strhex((unsigned char *)buf, size, &result);
        //printf("result : %s\n", result);
        __android_log_print(ANDROID_LOG_INFO, "KGW-N2", "%s: array = %s", message, result);
        free(result);
    }

    //
    //  Taken from bitcoinj, but optimized
    //
    void decodeMPI(unsigned char * mpi, int length, mpz_t * result) {
           //__android_log_print(ANDROID_LOG_INFO, "decodeMPI", "haslength %d", length);
        unsigned char * buf = 0;
        //int length = 0;
        if (length != 0) {
            //length = (int) readUint32(mpi, 0);
             //__android_log_print(ANDROID_LOG_INFO, "decodeMPI", "read %d", length);
            //buf = new char[length];
            //System.arraycopy(mpi, 4, buf, 0, length);
            //memcpy(buf, mpi+4, length);
			buf = mpi + 4;
			//print_array(mpi, length, "decodeMPI mpi");
			//print_array(buf, length, "decodeMPI mpi+4");
           //  __android_log_print(ANDROID_LOG_INFO, "decodeMPI", "memcpy");
        } //else
            //buf = mpi;
        if (length == 0)//this is taken from Java where the length of an array is known.
        {
            //return BigInteger.ZERO;
            mpz_init_set_ui(*result, 0);
            return;
        }
        bool isNegative = (buf[0] & 0x80) == 0x80;
        if (isNegative)
            buf[0] &= 0x7f;
        //BigInteger result = new BigInteger(buf);
        // __android_log_print(ANDROID_LOG_INFO, "decodeMPI", "check negative");
        //mpz_init(*result);
       // __android_log_print(ANDROID_LOG_INFO, "decodeMPI", "init result");
        mpz_import(*result, length, 1, sizeof(unsigned char), 1, 0, (void*)buf);
//         __android_log_print(ANDROID_LOG_INFO, "decodeMPI", "import result");
        if(isNegative)
            mpz_neg(*result, *result);
        //if(buf)
            //delete buf;

        //return isNegative ? result.negate() : result;
    }
    //
    // Taken from BitcoinJ.
    //
    void decodeCompactBits(long compact, mpz_t * result) {

        int size = ((int) (compact >> 24)) & 0xFF;
        bool needsLarger = size > 32;
        unsigned char* bytes;// = new char[4+size];
        static unsigned char _bytes[32 + 4];
        if(needsLarger)
            bytes = new unsigned char [4+size];
        else bytes = _bytes;
        //print_array(bytes, size, "decodeCompactBits allocated buffer");
        memset(bytes, 0, size+4);
        //print_array(bytes, size, "decodeCompactBits memset 0");
        bytes[3] = (char) size;
        if (size >= 1) bytes[4] = (unsigned char) ((compact >> 16) & 0xFF);
        if (size >= 2) bytes[5] = (unsigned char) ((compact >> 8) & 0xFF);
        if (size >= 3) bytes[6] = (unsigned char) ((compact >> 0) & 0xFF);
        //print_array(bytes, size, "decodeCompactBits set bytes");
        decodeMPI(bytes, size, result);
        //print_array(bytes, size, "decodeCompactBits decoded");
        if(needsLarger)
            delete bytes;
    }

//
// Second Optimization of the Loop.
//  This method takes a jlong for BlockReading Difficulty and converts it to a BIGNUM.  This saves 5% of the calculation time compared to the Original Java implementation.
//

unsigned int static KimotoGravityWell_loop2(JNIEnv * env, jclass cls,jint i, jlong BlockReadingDiff, jint BlockReadingHeight, jlong BlockReadingTime, jlong BlockLastSolvedTime) {


		if (PastBlocksMax > 0 && i > PastBlocksMax) { return STOP; }
		PastBlocksMass++;

		if (i == 1)
		{
		    //PastDifficultyAverage.SetCompact(BlockReading->nBits);
		    //__android_log_print(ANDROID_LOG_INFO, "KGW-N2", "%d: diff number is = %lx", BlockReadingHeight, BlockReadingDiff);
		    decodeCompactBits(BlockReadingDiff, &PastDifficultyAverage);

            //char S[128];
		    //mpz_get_str(S, 16, PastDifficultyAverage);
		    //convert_j2mp(env, BlockReadingDiff, &PastDifficultyAverage);
		    //__android_log_print(ANDROID_LOG_INFO, "KGW-N2", "%d: diff number is = %s", BlockReadingHeight, S);

		}
		else
		{
		    //PastDifficultyAverage = ((CBigNum().SetCompact(BlockReading->nBits) - PastDifficultyAveragePrev) / i) + PastDifficultyAveragePrev;
		    //mpz_t thisDiff, I;

		    //convert_j2mp(env, BlockReadingDiff, &thisDiff);
		    decodeCompactBits(BlockReadingDiff, &CurrentDifficulty);
		    mpz_set_si(CurrentIteration, i);
            //mpz_init(R);


            mpz_sub(PastDifficultyAverage, CurrentDifficulty, PastDifficultyAveragePrev);
            mpz_tdiv_q(PastDifficultyAverage, PastDifficultyAverage, CurrentIteration);
            mpz_add(PastDifficultyAverage, PastDifficultyAverage, PastDifficultyAveragePrev);
            //mpz_clear(I);
            //mpz_clear(thisDiff);
		}
		//PastDifficultyAveragePrev = PastDifficultyAverage;
		mpz_set(PastDifficultyAveragePrev, PastDifficultyAverage);

		PastRateActualSeconds			= BlockLastSolvedTime - BlockReadingTime;
		PastRateTargetSeconds			= TargetBlocksSpacingSeconds * PastBlocksMass;
		PastRateAdjustmentRatio			= double(1);
		if (PastRateActualSeconds < 0) { PastRateActualSeconds = 0; }
		if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
		PastRateAdjustmentRatio			= double(PastRateTargetSeconds) / double(PastRateActualSeconds);
		}
		EventHorizonDeviation			= 1 + (0.7084 * pow((double(PastBlocksMass)/double(DeviationDenominator)), -1.228));
		EventHorizonDeviationFast		= EventHorizonDeviation;
		EventHorizonDeviationSlow		= 1 / EventHorizonDeviation;

		if (PastBlocksMass >= PastBlocksMin) {
        			if ((PastRateAdjustmentRatio <= EventHorizonDeviationSlow) || (PastRateAdjustmentRatio >= EventHorizonDeviationFast)) { return STOP; }
        		}
        return CONTINUE;
}
//
// First Optimization of the Loop.
//  This method takes a byte[] for BlockReading Difficulty and converts it to a BIGNUM.  This requires that the Java Implemation convert the difficulty to the byte[] from a BigInteger.
//  This method saves 43% of the time compared to the java implementation
//

unsigned int static KimotoGravityWell_loop(JNIEnv * env, jclass cls,jint i, jbyteArray BlockReadingDiff, jint BlockReadingHeight, jlong BlockReadingTime, jlong BlockLastSolvedTime) {


		if (PastBlocksMax > 0 && i > PastBlocksMax) { return STOP; }
		PastBlocksMass++;

		if (i == 1)
		{
		    //PastDifficultyAverage.SetCompact(BlockReading->nBits);
		    convert_j2mp(env, BlockReadingDiff, &PastDifficultyAverage);

		}
		else
		{
		    //PastDifficultyAverage = ((CBigNum().SetCompact(BlockReading->nBits) - PastDifficultyAveragePrev) / i) + PastDifficultyAveragePrev;
		    mpz_t thisDiff, I;

		    convert_j2mp(env, BlockReadingDiff, &thisDiff);
		    mpz_init_set_si(I, i);
            //mpz_init(R);


            mpz_sub(PastDifficultyAverage, thisDiff, PastDifficultyAveragePrev);
            mpz_tdiv_q(PastDifficultyAverage, PastDifficultyAverage, I);
            mpz_add(PastDifficultyAverage, PastDifficultyAverage, PastDifficultyAveragePrev);
            mpz_clear(thisDiff);
            mpz_clear(I);
		}
		//PastDifficultyAveragePrev = PastDifficultyAverage;
		mpz_set(PastDifficultyAveragePrev, PastDifficultyAverage);

		PastRateActualSeconds			= BlockLastSolvedTime - BlockReadingTime;
		PastRateTargetSeconds			= TargetBlocksSpacingSeconds * PastBlocksMass;
		PastRateAdjustmentRatio			= double(1);
		if (PastRateActualSeconds < 0) { PastRateActualSeconds = 0; }
		if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
		PastRateAdjustmentRatio			= double(PastRateTargetSeconds) / double(PastRateActualSeconds);
		}
		EventHorizonDeviation			= 1 + (0.7084 * pow((double(PastBlocksMass)/double(DeviationDenominator)), -1.228));
		EventHorizonDeviationFast		= EventHorizonDeviation;
		EventHorizonDeviationSlow		= 1 / EventHorizonDeviation;

		if (PastBlocksMass >= PastBlocksMin) {
        			if ((PastRateAdjustmentRatio <= EventHorizonDeviationSlow) || (PastRateAdjustmentRatio >= EventHorizonDeviationFast)) { return STOP; }
        		}
        return CONTINUE;
}

//
//  This method closes the
//
jbyteArray KimotoGravityWell_close(JNIEnv * env, jclass cls)
{
	mpz_t bnNew;
	mpz_init_set(bnNew, PastDifficultyAverage);


	if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
	    mpz_t mpzPastRateActualSeconds;
        mpz_t mpzPastRateTargetSeconds;

        mpz_init_set_si(mpzPastRateActualSeconds, PastRateActualSeconds);
        mpz_init_set_si(mpzPastRateTargetSeconds, PastRateTargetSeconds);
		//bnNew *= PastRateActualSeconds;
		mpz_mul(bnNew, bnNew, mpzPastRateActualSeconds);
		//bnNew /= PastRateTargetSeconds;
		mpz_tdiv_q(bnNew, bnNew, mpzPastRateTargetSeconds);

        jbyteArray result;
		convert_mp2j(env, bnNew, &result);

        // cleanup all the bignums
        mpz_clear(bnNew);
        mpz_clear(mpzPastRateActualSeconds);
        mpz_clear(mpzPastRateTargetSeconds);
        mpz_clear(PastDifficultyAverage);
        mpz_clear(PastDifficultyAveragePrev);

        mpz_clear(CurrentIteration);
        mpz_clear(CurrentDifficulty);

		return result;
	}
	return NULL;
}

static const JNINativeMethod methods[] = {
    //{ "calculatePastDifficultyAverage2", "(ILjava/lang/String;Ljava/lang/String;)Ljava/lang/String;", (void *)calculatePastDifficultyAverage2  }
    //{ "cpda", "(I[B[B)[B", (void *)cpda  },
    { "KimotoGravityWell_close", "()[B", (void*)KimotoGravityWell_close},
    { "KimotoGravityWell_init", "(JJJD)I", (void*)KimotoGravityWell_init},
    { "KimotoGravityWell_loop", "(I[BIJJ)I", (void*)KimotoGravityWell_loop},
    { "KimotoGravityWell_loop2", "(IJIJJ)I", (void*)KimotoGravityWell_loop2},


};

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;

    if ((vm)->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return -1;
    }

    jclass cls = (env)->FindClass("hashengineering/difficulty/KimotoGravityWell/kgw");
    int r = (env)->RegisterNatives(cls, methods, 4);

    return (r == JNI_OK) ? JNI_VERSION_1_6 : -1;
}