/*
 * Crowd Fund (ported from solidity-by-example)
 * https://solidity-by-example.org/app/crowd-fund/
 *
 * Crowd fund ERC20 token:
 *   1. User creates a campaign.
 *   2. Users can pledge, transferring their token to a campaign.
 *   3. After the campaign ends, campaign creator can claim the funds if total
 *      amount pledged is more than the campaign goal.
 *   4. Otherwise, campaign did not reach it's goal, users can withdraw their
 *      pledge.
 *
 * The functionality of the below port should be
 * more-or-less identical to the solidity example.
 */

pragma license "MIT"
pragma solc "^0.8.17"
pragma yulc "^0.0.0"

/*
 * Configuration (via macro)
 */

// Uncomment to remove the `end_at` limit,
// or pass -DNO_LIMIT on the command line.
// macro NO_LIMIT := 1

@if iszero(defined(MAX_DAYS)) {
  macro MAX_DAYS := 90
}

// The equivalent of the above in C preprocessor:
// #ifndef MAX_DAYS
// #  define MAX_DAYS 90
// #endif

/*
 * ERC20 Interface
 */

interface ERC20 {
  method transfer(address, uint256) returns (bool)
  method transferFrom(address, address, uint256) returns (bool)
}

/**
 * @title Crowd Fund
 * @notice This is just here to prove we support
 *         parsing of NatSpec comments. This will
 *         be output in `yulc --interface`.
 */
contract CrowdFund {
  /**
   * @param The ERC20 token address.
   */
  constructor(address token) {
    require(token, "token == address(0)")
    storeimmutable("token", token)
  }

  /*
   * Constants
   */

  const DAY := 86400

  /*
   * Structs (storage)
   */

  // Total count of campaigns created.
  // It is also used to generate id for new campaigns.
  struct count_key {
    uint8 prefix := 1
  }

  // Single-member struct not necessary:
  // struct count { uint64 id }

  // Mapping from id to campaign.
  struct campaign_key {
    uint8 prefix := 2
    uint64 id
  }

  struct campaign {
    // Creator of campaign.
    address creator
    // Timestamp of start of campaign.
    uint32 start_at
    // Timestamp of end of campaign.
    uint32 end_at
    // True if goal was reached and creator has claimed the tokens.
    bool claimed
  }

  // Mapping from id to campaign values.
  struct values_key {
    uint8 prefix := 3
    uint64 id
  }

  struct values {
    // Amount of tokens to raise.
    uint128 goal
    // Total amount pledged.
    uint128 pledged
  }

  // Mapping from campaign id => pledger => amount pledged.
  struct pledge_key {
    uint8 prefix := 4
    uint64 id
    address pledger
  }

  // Single-member struct not necessary:
  // struct pledged { uint128 amount }

  /*
   * Struct Notes
   */

  // Unlike the solidity example, we have to
  // split up our structs as we are limited
  // to 32-byte stack-based structs (packed).

  // As we can see, `campaign` is only 225 bits.
  @if neq(bitsof(campaign), 225) {
    revert.static("unreachable")
  }

  // And `values` is exactly 32 bytes.
  assert.static(eq(sizeof(values), 32))

  /*
   * ERC20 Helpers
   */

  // The parentheses denote that this expression
  // should be wrapped in a non-inlinable function.
  // This can save a lot of gas on deployment.
  const TOKEN() := loadimmutable("token")

  // Some macros to make the interface calls less verbose.
  macro transfer(to, amount) :=
    call ERC20.transfer(0, TOKEN, to, amount)

  macro transferFrom(from, to, amount) :=
    call ERC20.transferFrom(0, TOKEN, from, to, amount)

  /*
   * Events
   */

  event Launch(uint64 id,
               address indexed creator,
               uint128 goal,
               uint32 start_at,
               uint32 end_at)

  event Cancel(uint64 id)
  event Pledge(uint64 indexed id, address indexed caller, uint128 amount)
  event Unpledge(uint64 indexed id, address indexed caller, uint128 amount)
  event Claim(uint64 id)
  event Refund(uint64 id, address indexed caller, uint128 amount)

  /*
   * Methods (i.e. external functions)
   */

  method launch(uint128 goal, uint32 start_at, uint32 end_at) {
    let goal := calldata.goal
    let start_at := calldata.start_at
    let end_at := calldata.end_at

    require.before(start_at, "start at < now")
    require.gte(end_at, start_at, "end at < start at")

    @if iszero(defined(NO_LIMIT)) { // #ifndef NO_LIMIT
      let max := add(timestamp(), mul(MAX_DAYS, DAY))
      require.lte(end_at, max, "end at > max duration")
    }

    let id := safeadd64(load_count(), 1)
    let campaign := struct(campaign, caller(), start_at, end_at, false)
    let values := struct(values, goal, 0)

    store_count(id)
    store_campaign(id, campaign)
    store_values(id, values)

    emit Launch(0, id, caller(), goal, start_at, end_at)
  }

  method cancel(uint64 id) {
    // Note: `campaign:@` is shorthand for `campaign:campaign`.
    let id := calldata.id
    let campaign:@ := load_campaign(id)

    require.caller(campaign->creator, "not creator")
    require.before(campaign->start_at, "started")

    store_campaign(id, 0)
    store_values(id, 0)

    emit Cancel(0, id)
  }

  method pledge(uint64 id, uint128 amount) {
    let id := calldata.id
    let amount := calldata.amount
    let c:campaign := load_campaign(id)

    require.after(c->start_at, "not started")
    require.before(c->end_at, "ended")

    let v:values := load_values(id)
    let pledged := load_pledged(id, caller())

    v->pledged := safeadd128(v->pledged, amount)
    pledged := safeadd128(pledged, amount)

    store_values(id, v)
    store_pledged(id, caller(), pledged)

    // Macro expansion:
    //   require(call ERC20.transferFrom(0, TOKEN, caller(), address(), amount))
    require(transferFrom(caller(), address(), amount))

    emit Pledge(0, id, caller(), amount)
  }

  method unpledge(uint64 id, uint128 amount) {
    let id := calldata.id
    let amount := calldata.amount
    let c:campaign := load_campaign(id)

    require.before(c->end_at, "ended")

    let v:values := load_values(id)
    let pledged := load_pledged(id, caller())

    v->pledged := safesub(v->pledged, amount)
    pledged := safesub(pledged, amount)

    store_values(id, v)
    store_pledged(id, caller(), pledged)

    // Macro expansion:
    //   require(call ERC20.transfer(0, TOKEN, caller(), amount))
    require(transfer(caller(), amount))

    emit Unpledge(0, id, caller(), amount)
  }

  method claim(uint64 id) {
    let id := calldata.id
    let c:campaign := load_campaign(id)
    let v:values := load_values(id)

    require.caller(c->creator, "not creator")
    require.after(c->end_at, "not ended")
    require.gte(v->pledged, v->goal, "pledged < goal")
    require.zero(c->claimed, "claimed")

    c->claimed := true

    store_campaign(id, c)

    // Macro expansion:
    //   require(call ERC20.transfer(0, TOKEN, c->creator, v->pledged))
    require(transfer(c->creator, v->pledged))

    emit Claim(0, id)
  }

  method refund(uint64 id) {
    let id := calldata.id
    let campaign:@ := load_campaign(id)
    let values:@ := load_values(id)

    require.after(campaign->end_at, "not ended")
    require.lt(values->pledged, values->goal, "pledged >= goal")

    let bal := load_pledged(id, caller())

    store_pledged(id, caller(), 0)

    // Macro expansion:
    //   require(call ERC20.transfer(0, TOKEN, caller(), bal))
    require(transfer(caller(), bal))

    emit Refund(0, id, caller(), bal)
  }

  /*
   * Views
   */

  // These are here in keeping with the public
  // nature of the storage in the solidity example.
  method count() view returns (uint64) {
    returns(0, load_count())
  }

  // Return the campaign struct(s) as a single tuple
  // (i.e. solidity-abi style). This is also in keeping
  // with the soldity example.
  method campaigns(uint64 id) view returns (address creator,
                                            uint128 goal,
                                            uint128 pledged,
                                            uint32 start_at,
                                            uint32 end_at,
                                            bool claimed) {
    let id := calldata.id
    let c:campaign := load_campaign(id)
    let v:values := load_values(id)

    returns(0, c->creator,
               v->goal,
               v->pledged,
               c->start_at,
               c->end_at,
               c->claimed)
  }

  method pledgedAmount(uint64 id, address pledger) view returns (uint128) {
    let pledged := load_pledged(calldata.id, calldata.pledger)

    // Since we are a superset of yul, we can
    // still return things the old-fashioned way:
    mstore(0, pledged)
    return(0, 32)
  }

  /*
   * Storage Helpers
   */

  // Some helper macros to initialize key structs.
  // Note that `@` is replaced with the default member value.
  macro count_key() := struct(count_key, @)
  macro campaign_key(id) := struct(campaign_key, @, id)
  macro values_key(id) := struct(values_key, @, id)
  macro pledge_key(id, pledger) := struct(pledge_key, @, id, pledger)

  function load_count() -> count {
    count := sload(count_key())
  }

  function store_count(count) {
    sstore(count_key(), count)
  }

  function load_campaign(id) -> result {
    result := sload(campaign_key(id))
    require(result, "not found")
  }

  function store_campaign(id, value) {
    sstore(campaign_key(id), value)
  }

  function load_values(id) -> result {
    result := sload(values_key(id))
  }

  function store_values(id, value) {
    sstore(values_key(id), value)
  }

  function load_pledged(id, pledger) -> result {
    result := sload(pledge_key(id, pledger))
  }

  function store_pledged(id, pledger, value) {
    sstore(pledge_key(id, pledger), value)
  }
}
