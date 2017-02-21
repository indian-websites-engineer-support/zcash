// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "streams.h"
#include "util.h"
#include "version.h"
#include "zcash/JoinSplit.hpp"
#include "zcash/Proof.hpp"

#include <vector>
#include <zmq.hpp>

#include "libsnark/common/profiling.hpp"

using namespace libzcash;

int main(int argc, char *argv[])
{
    SetupEnvironment();

    libsnark::inhibit_profiling_info = true;
    libsnark::inhibit_profiling_counters = true;

    auto p = ZCJoinSplit::Unopened();
    p->setProvingKeyPath((ZC_GetParamsDir() / "sprout-proving.key").string());
    p->loadProvingKey();

    zmq::context_t context(1);
    zmq::socket_t socket(context, ZMQ_REP);
    socket.bind("tcp://*:5555");

    while (true)
    {
        zmq::message_t request;
        socket.recv(&request);

        const char *data = (const char *)request.data();
        CDataStream ssWitnesses(data, data + request.size(), SER_NETWORK, PROTOCOL_VERSION);
        std::vector<ZCJSProofWitness> witnesses;
        ssWitnesses >> witnesses;
        std::cout << "Received " << witnesses.size() << " witnesses!" << std::endl;

        std::cout << "- Running prover…" << std::flush;
        std::vector<ZCProof> proofs;
        for (auto witness : witnesses)
        {
            proofs.push_back(p->prove(witness));
            std::cout << "…" << std::flush;
        }

        CDataStream ssProofs(SER_NETWORK, PROTOCOL_VERSION);
        ssProofs << proofs;
        std::vector<unsigned char> serialized(ssProofs.begin(), ssProofs.end());

        zmq::message_t reply(serialized.size());
        memcpy(reply.data(), serialized.data(), serialized.size());
        socket.send(reply);
        std::cout << " Done!" << std::endl;
    }
}
