/*

// A header is a small set of data which commits to a unique update.
// With high probability, it proves round r update correctness to anyone with
// (1) root state at round r (correctness: state in prev hash goes to state) (if it gets signed)
// (2) the previous matching header in (agreement: state in prev hash is the current state)
// Currently just for root updates probably will create different struct...
Header:
  - Round
  - Timestamp
  - Prev hash
  - State hash
  - Txn group hash
  - Seed

// Block provides information to run header update with current state.
Block:
 - Header
 - Txns

// Snapshot provides information to load current state.
Snapshot:
 - Block
 - State

State:
 - Stakes

// In principle could easily store txn history / state history but not relevant for this testing...
Node:
 - Keypair
 - History[FORK_MAX] (at round % FORK_MAX get HashMap: hash -> snapshot)
 - Curr (current snapshot)


*/
