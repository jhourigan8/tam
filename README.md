# tammany

Early stage code exploring a potential optimization in optimistic rollups.

## background

Optimistic rollups are a particular kind of solution to the scaling bottlenecks faced by L1 blockchains.
Although implementations can vary, the following is a relatively representative concrete protocol.

 - There is 1 **sequencer** node who periodically processes transactions for the L2 and posts the transaction batch (often significantly compressed) + new state root on the L1.
 - There are N ~= 10 **validator** nodes who have the rollup state. They make this publicly available to anyone who requests it.
 - The validators read the transaction batches and verify the state transition; if incorrect, they post a succinct **fraud proof** showing that the state transition was computed incorrectly. If the fraud proof is correct, the sequencer will have their state slashed, a new validator will be chosen as sequencer, and the incorrect transition will be reverted.
 - Validators regularly post unprocessed transaction batches that they receive on the L1. The sequencer is required to process these in a timely manner or else they will be slashed.

In a relatively weak 1 of N trust model (i.e., we assume at least one validator is honest) the L2 has the following standard set of guarantees:

 1. **Secure**: __An invalid state transition cannot occur__. If the sequencer posts an invalid transition, the honest validator can tell since they have the transaction batch. So they will post a fraud proof.
 2. **Available**: __All state and transaction history is publicly available__. This is simply because an honest validator will make the transaction and state history public.
 3. **Censorship Resistant**: __Anyone can submit a transaction to the L2__. By submitting your transaction to each validator, the honest validator will soon publish it in a batch on the L1, and the sequencer will have to process it.

Notice that L1 nodes do not have to verify computations (unless a fraud proof is posted), but they do need to store the entire transaction batches.
This presents a bottleneck for rollups: the size of transaction data processed by the L2 is necessarily bounded by the bandwidth of the slowest L1 nodes.

## proof of availability

For guarantees (1) and (3) to hold, we don't precisely need that transaction batches are posted on the L1.
Concretely, it suffices for the sequencer / a validator to prove to the L1 that the batch is made available to all other validators: an honest validator is still able to track the state, and the sequencer is still able to include the set of transactions posted by a validator.
Then our protocol should have the following properties:

 - If a malicious validator posts commit(x) on the L1 and does not make x available to other validators, the L1 nodes can tell and penalize the nalicious validator.
 - If a malicious validator posts commit(x) on the L1 and tries to make a value y =/= x available, the other validators can efficiently prove that this is the case and the malicious validator is penalized.
 - If a validator posts commit(x) and makes x available, they cannot be penalized.

With such a protocol, we can replace all instances of posting transaction batches with posting a commit and proving availability.
If the protocol is efficient enough, the L1 node bandwith bottleneck no longer affects the scalability of the L2.

## error correcting codes

Given a file of size M, one can use error correcting codes to efficiently construct a code of size 3M such that any third of the code suffices to reconstruct the file.
We call each chunk of the resulting code a share.
Using this primitive, we can design the following protocol for a validator making a batch x available:

 - The validator posts commit(x) on the L1. Then, they compute ecc(x), sign each share, and send to each L1 node a number of shares proportional to the node's stake.
 - The L1 nodes who receive shares forward their shares to the other validators.
 - The L1 nodes who didn't receive shares complain on the L1 accusing the validator of being malicious unless they have already done so in the "recent" past. If >= 1/3 of the nodes complained now or "recently", the validator is penalized.
 - If the other validators get enough shares, they can compute the file y which the first validator shared.
 - If commit(y) =/= commit(x) the other validators post all the shares on chain, proving that the first validator shared the wrong file. If this is indeed the case, the first validator is penalized.

Assume less than 1/3 of L1 nodes are malicious (as is relatively standard).
If the validator does not send >= 1/3 of the shares to honest nodes, then >= 1/3 of the L1 nodes complain and they are penalized.
Conversely, if the validator does send >= 1/3 of the shares to honest nodes, all other validators have enough shares to reconstruct the file.
If the validator shares some y =/= x, the other validators will prove this and the first validator will be penalized.
If instead the validator shares x, the other validators cannot prove them wrong, and the malicious L1 nodes all complaining cannot cause the validator to be penalized.
So this protocol has all the properties we desire.

## efficiency, and an optimization

With the sharing scheme, an L1 node with 1/1000 of the stake has to receive and send about 1/1000 of the transaction batch size.
So compared to a standard optimistic rollup, the size of transaction batches can now bounded by the bandwidth of __all__ L1 nodes, rather than by each L1 node.
On an L1 with 1000 nodes, this represents a potential ~1000x speedup.
The efficiency when things go wrong is a bit worse.
Each L1 node may complain about each validator, but so long as complaints are not repeated frequently the cost of this is relatively low.

If a validator receives y =/= x, they need to post all sharings on the L1, which is tantamount to posting the whole batch x itself.
Since we wish to allow x to be very large, this is not ideal.
A moderatley complex fix is the following: instead of sharing x, the validator shares many nodes in a merkle tree encoding x, each of far smaller size than x itself (e.g., each of size Theta(# of L1 nodes), so each share is constant size).
If this was done incorrectly, then at most two merkle nodes need to be posted and reconstructed on the L1 to prove this is the case.
This is not too costly.
