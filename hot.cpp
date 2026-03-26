
#include <crapto1.h>
#include <algorithm>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <fstream>
#include <iostream>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

namespace py = pybind11;


#define TOLERANCE 25

uint64_t tmpPossibleKey;

std::unordered_map<uint64_t, uint32_t> keyMap;
std::unordered_set<uint64_t> triedKeys;



typedef uint8_t byte;

uint64_t findKey();

uint8_t oddparity(const uint8_t bt)
{
  return (0x9669 >> ((bt ^(bt >> 4)) & 0xF)) & 1;
}

uint8_t isNonce( uint32_t Nt, uint32_t NtEnc, uint32_t Ks1 , uint8_t *parity)
{
    /*
     * the parities of the first 3 nonce bytes are encrypted with ks1' bit 8, 16, 24, these must be equal 
     * to the ones we extracted from the encrypted session. 
     */
   
    return ((oddparity((Nt >> 24) & 0xFF) == ((parity[0]) ^ oddparity((NtEnc >> 24) & 0xFF) ^ BIT(Ks1, 16))) & \
          (oddparity((Nt >> 16) & 0xFF) == ((parity[1]) ^ oddparity((NtEnc >> 16) & 0xFF) ^ BIT(Ks1, 8))) & \
	    (oddparity((Nt >> 8) & 0xFF) == ((parity[2]) ^ oddparity((NtEnc >> 8) & 0xFF) ^ BIT(Ks1, 0)))) ? 1 : 0;
}// isNonce



int nonce_distancer( uint32_t Nonce1, uint32_t Nonce2) {
    return nonce_distance(Nonce1, Nonce2);
}

void generatePossibleKeys( uint32_t cryptostate,  uint32_t encNt, uint32_t medianDist, uint64_t uid, py::buffer nonceParity) {
    py::buffer_info info = nonceParity.request();

    if (info.ndim != 1) {
        throw std::runtime_error("Expected 1D buffer");
    }
    if (info.itemsize != sizeof(uint8_t)) {
        throw std::runtime_error("Expected byte-sized elements");
    }

    if (info.shape[0] != 3) {
    throw std::runtime_error("Unexpected buffer length");
    }

    auto *data = static_cast<uint8_t *>(info.ptr);


    //Hot recovery loops

    struct Crypto1State *revstate;
    struct Crypto1State *revstateStart;
    uint32_t ks1; //keystream 1

    uint32_t guessNt = prng_successor(cryptostate, medianDist - TOLERANCE);

    for (int i = (medianDist - TOLERANCE); i <= (medianDist + TOLERANCE); i+=2){
        ks1 = encNt ^ guessNt; //try to recover keystream 1
        revstateStart = nullptr;

        if (isNonce(guessNt, encNt, ks1, data)){ //

            revstate = lfsr_recovery32(ks1, guessNt ^ uid);

            if (revstateStart == nullptr) {
                revstateStart = revstate;
            }
            while ((revstate->odd != 0x00) || (revstate->even != 0x00)) {
                lfsr_rollback_word(revstate, guessNt ^ uid, 0);
                crypto1_get_lfsr(revstate, &tmpPossibleKey);

                ++keyMap[tmpPossibleKey];

                revstate++;
            }
            free(revstateStart);
        }
        guessNt = prng_successor(guessNt,2);
    }
}


uint64_t findKey() {
    uint32_t highestCount = 0;
    uint64_t bestKey = 0;
    std::vector<uint32_t> countArray;
    for (auto &kc : keyMap){
        // if (kc.second > 1){
        //     printf("%012llx\n", kc.first);
        // }
        if (kc.second > countArray.size()){
            countArray.resize(kc.second, 0);
        }
        countArray[kc.second-1] += 1;
        if (kc.second > highestCount && (triedKeys.count(kc.first) == 0)){
            highestCount = kc.second;
            bestKey = kc.first;
        }
    }
    for (int i = 0 ; i<countArray.size(); i++){
            printf("%d keys repeating %d times\n", countArray[i], i+1);
        }
    // for (auto &k : triedKeys){
    //         printf("tried %012llx already\n", k);
    //     }    
    printf("trying %012llx with %d hits\n", bestKey, keyMap[bestKey]);
    triedKeys.emplace(bestKey);
    return bestKey;
}


PYBIND11_MODULE(hot, m) {
    m.def("nonce_distancer", &nonce_distancer);
    m.def("generatePossibleKeys", &generatePossibleKeys);
    m.def("findKey", &findKey);
}



/*

if( counter > maxCount )
	    {
            maxCount = counter;
            candidateKey = allKeys[i];
            bestKeyIndex = i;
            // printf("%d hits on %012llx\n", counter, candidateKey);
            
	    }
	    
	    counter = 0;
	}
    if (candidateKey != 0){
        allKeys.erase(allKeys.begin()+(bestKeyIndex-maxCount),allKeys.begin()+(bestKeyIndex)); //consume key
        for (int j = bestKeyIndex-maxCount ; j < bestKeyIndex ; j++){
            printf("erasing %012llx\n with %d hits\n", allKeys[j], (maxCount));
        }
    }
            
*/