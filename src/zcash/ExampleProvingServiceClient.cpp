// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "../util.h"
#include "primitives/transaction.h"
#include "streams.h"
#include "utilstrencodings.h"
#include "version.h"
#include "zcash/JoinSplit.hpp"
#include "zcash/Proof.hpp"

#include <vector>
#include <zmq.hpp>

#include "libsnark/common/profiling.hpp"

using namespace libzcash;

int main(int argc, char **argv)
{
    SetupEnvironment();

    libsnark::inhibit_profiling_info = true;
    libsnark::inhibit_profiling_counters = true;

    auto p = ZCJoinSplit::Unopened();
    p->loadVerifyingKey((ZC_GetParamsDir() / "sprout-verifying.key").string());

    int32_t numJSDescs = 5;
    if (argc > 1) {
        ParseInt32(std::string(argv[1]), &numJSDescs);
    }
    if (numJSDescs <= 0) {
        std::cerr << "Usage: ExampleProvingServiceClient (numJSDescs)" << std::endl;
        std::cerr << "If provided, numJSDescs must be a positive integer." << std::endl;
        return 1;
    }

    zmq::context_t context(1);
    zmq::socket_t socket(context, ZMQ_REQ);

    std::cout << "Connecting to proving server…" << std::endl;
    socket.connect("tcp://localhost:5555");

    // construct several proofs.
    uint256 anchor = ZCIncrementalMerkleTree().root();
    uint256 pubKeyHash;
    std::vector<JSDescription> jsdescs;
    std::vector<ZCJSProofWitness> witnesses;
    for (size_t i = 0; i < numJSDescs; i++)
    {
        JSDescription jsdesc(*p,
                             pubKeyHash,
                             anchor,
                             {JSInput(), JSInput()},
                             {JSOutput(), JSOutput()},
                             0,
                             0,
                             false);
        jsdescs.push_back(jsdesc);
        witnesses.push_back(jsdesc.witness);
    }

    CDataStream ssWitnesses(SER_NETWORK, PROTOCOL_VERSION);
    ssWitnesses << witnesses;
    std::vector<unsigned char> serialized(ssWitnesses.begin(), ssWitnesses.end());

    zmq::message_t request(serialized.size());
    memcpy(request.data(), serialized.data(), serialized.size());
    std::cout << "Sending witnesses…" << std::endl;
    socket.send(request);

    std::cout << "- Waiting for proofs…" << std::endl;
    zmq::message_t reply;
    socket.recv(&reply);

    const char *data = (const char *)reply.data();
    CDataStream ssProofs(data, data + reply.size(), SER_NETWORK, PROTOCOL_VERSION);
    std::vector<ZCProof> proofs;
    ssProofs >> proofs;

    for (size_t i = 0; i < numJSDescs; i++)
    {
        jsdescs[i].proof = proofs[i];
        std::cout << "- Checking validity of proof " << i << "…" << std::flush;
        auto verifier = ProofVerifier::Strict();
        if (jsdescs[i].Verify(*p, verifier, pubKeyHash))
        {
            std::cout << " Valid!" << std::endl;
        }
        else
        {
            std::cout << " Invalid!" << std::endl;
            return 1;
        }
    }
}
