// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Copyright (c) 2017 Ahmad A Kazi (Empinel/Plaxton)
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PRIME_PRIME_H
#define PRIME_PRIME_H

#include <boost/thread/tss.hpp>

#include <prime/bignum.h>

#include <util.h>
#include <chain.h>
#include <validation.h>
#include <primitives/transaction.h>
#include <primitives/block.h>

#if defined(_MSC_VER) || defined(__MSVCRT__)
#define PRI64d  "I64d"
#define PRI64u  "I64u"
#define PRI64x  "I64x"
#else
#define PRI64d  "lld"
#define PRI64u  "llu"
#define PRI64x  "llx"
#endif

static const unsigned int nMaxSieveSize = 1000000u;
static const arith_uint256 hashBlockHeaderLimit = (arith_uint256(1) << 255);
static const CBigNum bnOne = 1;
static const CBigNum bnPrimeMax = (bnOne << 2000) - 1;
static const CBigNum bnPrimeMin = (bnOne << 255);

// Generate small prime table
void GeneratePrimeTable();
// Get next prime number of p
bool PrimeTableGetNextPrime(unsigned int& p);
// Get previous prime number of p
bool PrimeTableGetPreviousPrime(unsigned int& p);

// Compute primorial number p#
void Primorial(unsigned int p, CBigNum& bnPrimorial);
// Compute the first primorial number greater than or equal to bn
void PrimorialAt(CBigNum& bn, CBigNum& bnPrimorial);

// Test probable prime chain for: bnPrimeChainOrigin
// fFermatTest
//   true - Use only Fermat tests
//   false - Use Fermat-Euler-Lagrange-Lifchitz tests
// Return value:
//   true - Probable prime chain found (one of nChainLength meeting target)
//   false - prime chain too short (none of nChainLength meeting target)
bool ProbablePrimeChainTest(const CBigNum& bnPrimeChainOrigin, unsigned int nBits, bool fFermatTest, unsigned int& nChainLengthCunningham1, unsigned int& nChainLengthCunningham2, unsigned int& nChainLengthBiTwin);

static const unsigned int nFractionalBits = 24;
static const unsigned int TARGET_FRACTIONAL_MASK = (1u<<nFractionalBits) - 1;
static const unsigned int TARGET_LENGTH_MASK = ~TARGET_FRACTIONAL_MASK;
static const uint64_t nFractionalDifficultyMax = (1llu << (nFractionalBits + 32));
static const uint64_t nFractionalDifficultyMin = (1llu << 32);
static const uint64_t nFractionalDifficultyThreshold = (1llu << (8 + 32));
static const unsigned int nWorkTransitionRatio = 32;
unsigned int TargetGetLimit(const Consensus::Params& consensus_params);
unsigned int TargetGetInitial(const Consensus::Params& consensus_params);
unsigned int TargetGetLength(unsigned int nBits);
bool TargetSetLength(unsigned int nLength, unsigned int& nBits);
unsigned int TargetGetFractional(unsigned int nBits);
uint64_t TargetGetFractionalDifficulty(unsigned int nBits);
bool TargetSetFractionalDifficulty(uint64_t nFractionalDifficulty, unsigned int& nBits);
std::string TargetToString(unsigned int nBits);
unsigned int TargetFromInt(unsigned int nLength);
bool TargetGetMint(unsigned int nBits, uint64_t& nMint, const Consensus::Params& consensus_params);
bool TargetGetNext(unsigned int nBits, int64_t nInterval, int64_t nTargetSpacing, int64_t nActualSpacing, unsigned int& nBitsNext, const Consensus::Params& consensus_params);

// Check prime proof-of-work
enum // prime chain type
{
    PRIME_CHAIN_CUNNINGHAM1 = 1u,
    PRIME_CHAIN_CUNNINGHAM2 = 2u,
    PRIME_CHAIN_BI_TWIN     = 3u,
};
bool CheckBlockHeaderIntegrity(uint256 hashBlockHeader, unsigned int nBits, const CBigNum& bnPrimeChainMultiplier, const Consensus::Params& consensus_params);
bool CheckPrimeProofOfWork(uint256 hashBlockHeader, unsigned int nBits, const CBigNum& bnPrimeChainMultiplier, unsigned int& nChainType, unsigned int& nChainLength, const Consensus::Params& consensus_params);
bool CheckPrimeProofOfWorkV02Compatibility(uint256 hashBlockHeader);

// prime target difficulty value for visualization
double GetPrimeDifficulty(unsigned int nBits);
// Estimate work transition target to longer prime chain
unsigned int EstimateWorkTransition(unsigned int nPrevWorkTransition, unsigned int nBits, unsigned int nChainLength);
// prime chain type and length value
std::string GetPrimeChainName(unsigned int nChainType, unsigned int nChainLength);
// primorial form of prime chain origin
std::string GetPrimeOriginPrimorialForm(CBigNum& bnPrimeChainOrigin);

// Mine probable prime chain of form: n = h * p# +/- 1
bool MineProbablePrimeChain(CBlock& block, CBigNum& bnFixedMultiplier, bool& fNewBlock, unsigned int& nTriedMultiplier, unsigned int& nProbableChainLength, unsigned int& nTests, unsigned int& nPrimesHit);

// Perform Fermat test with trial division
// Return values:
//   true  - passes trial division test and Fermat test; probable prime
//   false - failed either trial division or Fermat test; composite
bool ProbablePrimalityTestWithTrialDivision(const CBigNum& bnCandidate, unsigned int nTrialDivisionLimit);

// Estimate the probability of primality for a number in a candidate chain
double EstimateCandidatePrimeProbability();

// Sieve of Eratosthenes for proof-of-work mining
class CSieveOfEratosthenes
{
    unsigned int nSieveSize; // size of the sieve
    unsigned int nBits; // target of the prime chain to search for
    uint256 hashBlockHeader; // block header hash
    CBigNum bnFixedFactor; // fixed factor to derive the chain

    // bitmaps of the sieve, index represents the variable part of multiplier
    std::vector<bool> vfCompositeCunningham1;
    std::vector<bool> vfCompositeCunningham2;
    std::vector<bool> vfCompositeBiTwin;

    unsigned int nPrimeSeq; // prime sequence number currently being processed
    unsigned int nCandidateMultiplier; // current candidate for power test

public:
    CSieveOfEratosthenes(unsigned int nSieveSize, unsigned int nBits, uint256 hashBlockHeader, CBigNum& bnFixedMultiplier)
    {
        this->nSieveSize = nSieveSize;
        this->nBits = nBits;
        this->hashBlockHeader = hashBlockHeader;
        this->bnFixedFactor = bnFixedMultiplier * CBigNum(hashBlockHeader);
        nPrimeSeq = 0;
        vfCompositeCunningham1 = std::vector<bool> (nMaxSieveSize, false);
        vfCompositeCunningham2 = std::vector<bool> (nMaxSieveSize, false);
        vfCompositeBiTwin = std::vector<bool> (nMaxSieveSize, false);
        nCandidateMultiplier = 0;
    }

    // Get total number of candidates for power test
    unsigned int GetCandidateCount()
    {
        unsigned int nCandidates = 0;
        for (unsigned int nMultiplier = 0; nMultiplier < nSieveSize; nMultiplier++)
        {
            if (!vfCompositeCunningham1[nMultiplier] ||
                !vfCompositeCunningham2[nMultiplier] ||
                !vfCompositeBiTwin[nMultiplier])
                nCandidates++;
        }
        return nCandidates;
    }

    // Scan for the next candidate multiplier (variable part)
    // Return values:
    //   True - found next candidate; nVariableMultiplier has the candidate
    //   False - scan complete, no more candidate and reset scan
    bool GetNextCandidateMultiplier(unsigned int& nVariableMultiplier, unsigned int& nCandidateType)
    {
        for(;;)
        {
            nCandidateMultiplier++;
            if (nCandidateMultiplier >= nSieveSize)
            {
                nCandidateMultiplier = 0;
                return false;
            }
            if (!vfCompositeBiTwin[nCandidateMultiplier])
            {
                nVariableMultiplier = nCandidateMultiplier;
                nCandidateType = PRIME_CHAIN_BI_TWIN;
                return true;
            }
            if (!vfCompositeCunningham1[nCandidateMultiplier])
            {
                nVariableMultiplier = nCandidateMultiplier;
                nCandidateType = PRIME_CHAIN_CUNNINGHAM1;
                return true;
            }
            if (!vfCompositeCunningham2[nCandidateMultiplier])
            {
                nVariableMultiplier = nCandidateMultiplier;
                nCandidateType = PRIME_CHAIN_CUNNINGHAM2;
                return true;
            }
        }
    }

    // Weave the sieve for the next prime in table
    // Return values:
    //   True  - weaved another prime
    //   False - sieve already completed
    bool Weave();
};

static const unsigned int nPrimorialMultiplierMin = 7;
static const unsigned int nSieveWeaveInitial = 1000;

class CPrimeMiner
{
    bool fSieveRoundShrink;
    unsigned int nSieveCandidateCount;
    int64_t nTimeSieveReady; // sieve ready timestamp in microsecond
    int64_t nPrimalityTestCost; // power test time cost in microsecond

 public:

    // Primorial multiplier
    unsigned int nPrimorialMultiplier;

    // Optimal sieve weave times (index to prime table)
    unsigned int nSieveWeaveOptimal;

    CPrimeMiner()
    {
        fSieveRoundShrink = true;
        nSieveCandidateCount = 0;
        nTimeSieveReady = 0;
        nPrimalityTestCost = 0;
        nPrimorialMultiplier = nPrimorialMultiplierMin;
        nSieveWeaveOptimal = nSieveWeaveInitial;
    }

    unsigned int GetSieveWeaveOptimalPrime();

    void SetSieveWeaveCost(int64_t nSieveWeaveCost, unsigned int nSieveWeaveComposites)
    {
        fSieveRoundShrink = (nSieveWeaveCost > nSieveWeaveComposites * nPrimalityTestCost);
    }

    void SetSieveWeaveCount(unsigned int nSieveWeaveCount);

    void AdjustSieveWeaveOptimal();

    int64_t GetPrimalityTestCost()
    {
        return nPrimalityTestCost;
    }

    void TimerSetSieveReady(unsigned int nCandidateCount, int64_t nTimestampMicro)
    {
        nSieveCandidateCount = nCandidateCount;
        nTimeSieveReady = nTimestampMicro;
    }

    void TimerSetPrimalityDone(int64_t nTimestampMicro)
    {
        if (nTimestampMicro > nTimeSieveReady && nSieveCandidateCount > 0)
            nPrimalityTestCost = (nTimestampMicro - nTimeSieveReady) / nSieveCandidateCount;
    }
};

extern boost::thread_specific_ptr<CPrimeMiner> pminer;

#endif