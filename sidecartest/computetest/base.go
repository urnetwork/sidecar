// computetest.FakeBase (CTEST-M13-03; DESIGN-COMPUTE §18's web search row, with §21.5): one fake Base chain, for
// SRCH's search signer, settlement watcher and payee screen and for FakeParallel's facilitator, served as two
// JSON-RPC sources, a CDP-like and an Alchemy-like (FakeBaseSource), as the signer reads Base twice.
//
//	chain      blocks from a genesis, each with its hash, parent and timestamp (its parent's plus the block interval,
//	           or the clock's time where later, as Base's two-second cadence keeps); a latest head, a safe head and a
//	           finalized head the test moves (Finalize, SetSafe); state replayed from the genesis allocation at any
//	           block, so a reorg undoes what it drops
//	usdc       one token at an address drawn from the seed, USDC's EIP-712 domain ("USD Coin", "2", the chain id, the
//	           contract): balanceOf, authorizationState and DOMAIN_SEPARATOR by eth_call; transferWithAuthorization's
//	           checks as FiatToken's (the window against the including block's timestamp, the nonce unused, the
//	           balance, and the signature recovered for real), its AuthorizationUsed then Transfer logs; a plain
//	           transfer's Transfer log alone
//	accounts   ETH balances, code and transaction counts the test sets for the payee screen; a sender's count rising
//	           with each transaction it sends
//	sends      TransferWithAuthorization from any sender, the facilitator's or another's (out of band), and Transfer from
//	           a holder (a transfer that settles no authorization); each mined at once into a block of its own
//	reorgs     Reorg replaces the unsafe head's last blocks with new ones of other hashes, keeping or dropping their
//	           transactions; a block at or below the safe head is never replaced
//	sources    eth_chainId, eth_blockNumber, eth_getBlockByNumber (latest, safe, finalized, pending, earliest or a
//	           number), eth_getBlockByHash, eth_getLogs (address and topics filters, a block range or a block hash, a
//	           range past the source's cap refused), eth_getCode, eth_getTransactionCount, eth_getBalance, eth_call,
//	           eth_getTransactionByHash and eth_getTransactionReceipt, single or batched, each source behind its own
//	           key in its path; a source can lag the chain (SetLag), report another hash for a block (Disagree) or be
//	           down (SetDown)
//
// Every address and hash is drawn from the seed or the chain's own counters, so one script on one seed and one clock
// makes the same chain. Nothing sleeps. Safe for concurrent use.

package computetest

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Base's chain id, and the token's EIP-712 name and version, USDC's (identifiers).
const (
	FakeBaseChainId     uint64 = 8453
	FakeBaseUsdcName           = "USD Coin"
	FakeBaseUsdcVersion        = "2"
)

// The two sources' kinds and hosts (identifiers).
type FakeBaseSourceKind string

const (
	FakeBaseCdp     FakeBaseSourceKind = "cdp"
	FakeBaseAlchemy FakeBaseSourceKind = "alchemy"

	FakeBaseCdpHost     = "base-mainnet.cdp.example"
	FakeBaseAlchemyHost = "base-mainnet.alchemy.example"
)

var (
	// A transaction the chain refuses, as FiatToken reverts it: a window that has not opened or has closed, a used or
	// canceled nonce, a balance short of the value, or a signature that recovers to someone else.
	ErrFakeBaseReverted = errors.New("computetest: the fake chain reverts the transaction")
	// A head moved where the chain cannot: a reorg reaching the safe head, or a finalized head past the latest.
	ErrFakeBaseHead = errors.New("computetest: the fake chain cannot move its head there")
)

// The chain's settings (QD-702).
type FakeBaseSettings struct {
	// The least a block's timestamp advances on its parent's: Base's 2 s.
	BlockInterval time.Duration
	// The most blocks one eth_getLogs may span on each source: stand-ins for each provider's own cap, 1,000 blocks on the
	// CDP-like source and 2,000 on the Alchemy-like one, which a reader must page under.
	CdpLogsBlockRangeMaxCount     uint64
	AlchemyLogsBlockRangeMaxCount uint64
	// The most calls one JSON-RPC batch holds: 100.
	BatchMaxCount int
	// The most bytes a request's body may hold: 1 MiB.
	RequestBodyMaxByteCount int64
}

// The chain's defaults, the only place one is set.
func DefaultFakeBaseSettings() *FakeBaseSettings {
	return &FakeBaseSettings{
		BlockInterval:                 2 * time.Second,
		CdpLogsBlockRangeMaxCount:     1000,
		AlchemyLogsBlockRangeMaxCount: 2000,
		BatchMaxCount:                 100,
		RequestBodyMaxByteCount:       1024 * 1024,
	}
}

// What NewFakeBase builds on.
type FakeBaseArgs struct {
	// Nil takes DefaultFakeBaseSettings.
	Settings *FakeBaseSettings
	// Every block's time; nil takes a FakeClock at sidecartest.DefaultClockStart.
	Clock sidecar.Clock
	// What its addresses, hashes and keys are drawn from; empty takes "computetest".
	Seed string
	// 0 takes FakeBaseChainId.
	ChainId uint64
}

// One log, as JSON-RPC answers it.
type FakeBaseLog struct {
	Address     FakeEvmAddress
	Topics      [][32]byte
	Data        []byte
	BlockNumber uint64
	BlockHash   [32]byte
	TxHash      [32]byte
	TxIndex     int
	LogIndex    int
}

// A transaction's receipt.
type FakeBaseReceipt struct {
	TxHash      [32]byte
	BlockNumber uint64
	BlockHash   [32]byte
	// The sender, the facilitator's address for a settlement through it.
	From FakeEvmAddress
	// Whether it succeeded where it was mined; a transaction a reorg re-included may revert there.
	Status bool
	Logs   []*FakeBaseLog
}

// What a transaction does.
type fakeBaseTxKind int

const (
	fakeBaseTransferWithAuthorization fakeBaseTxKind = iota
	fakeBaseTransfer
)

type fakeBaseTx struct {
	hash      [32]byte
	sender    FakeEvmAddress
	kind      fakeBaseTxKind
	auth      *FakeTransferAuthorization
	signature []byte
	// a plain transfer's
	from  FakeEvmAddress
	to    FakeEvmAddress
	value *big.Int
	// as applied in its block: its sender's count before it, its status and logs
	senderNonce uint64
	status      bool
	logs        []*FakeBaseLog
}

type fakeBaseBlock struct {
	number     uint64
	hash       [32]byte
	parentHash [32]byte
	timestamp  uint64
	txs        []*fakeBaseTx
}

// One account's state.
type fakeBaseAccount struct {
	eth   *big.Int
	usdc  *big.Int
	code  []byte
	count uint64
}

// The state at a block: accounts and the token's authorization states.
type fakeBaseState struct {
	accounts map[FakeEvmAddress]*fakeBaseAccount
	used     map[FakeEvmAddress]map[[32]byte]bool
}

func (self *fakeBaseState) account(address FakeEvmAddress) *fakeBaseAccount {
	account, ok := self.accounts[address]
	if !ok {
		account = &fakeBaseAccount{eth: new(big.Int), usdc: new(big.Int)}
		self.accounts[address] = account
	}
	return account
}

func (self *fakeBaseState) clone() *fakeBaseState {
	clone := &fakeBaseState{accounts: map[FakeEvmAddress]*fakeBaseAccount{}, used: map[FakeEvmAddress]map[[32]byte]bool{}}
	for address, account := range self.accounts {
		clone.accounts[address] = &fakeBaseAccount{
			eth:   new(big.Int).Set(account.eth),
			usdc:  new(big.Int).Set(account.usdc),
			code:  slices.Clone(account.code),
			count: account.count,
		}
	}
	for address, nonces := range self.used {
		clone.used[address] = map[[32]byte]bool{}
		for nonce := range nonces {
			clone.used[address][nonce] = true
		}
	}
	return clone
}

// See the file header.
type FakeBase struct {
	settings *FakeBaseSettings
	clock    sidecar.Clock
	seed     string
	chainId  uint64
	usdc     FakeEvmAddress
	https    *fakeHttpsServer
	sources  map[FakeBaseSourceKind]*FakeBaseSource

	stateLock sync.Mutex
	genesis   *fakeBaseState
	blocks    []*fakeBaseBlock
	safe      uint64
	finalized uint64
	// the state at the latest block, replayed after each change
	latest *fakeBaseState
	// counts the blocks and transactions ever made, so a reorg's blocks and a new transaction draw new hashes
	blockCount uint64
	txCount    uint64
}

// A chain with its genesis block, both sources listening on loopback at once; Close ends them.
func NewFakeBase(args *FakeBaseArgs) (*FakeBase, error) {
	if args == nil {
		args = &FakeBaseArgs{}
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultFakeBaseSettings()
	}
	clock := args.Clock
	if clock == nil {
		clock = sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	}
	seed := args.Seed
	if seed == "" {
		seed = "computetest"
	}
	chainId := args.ChainId
	if chainId == 0 {
		chainId = FakeBaseChainId
	}
	https, err := newFakeHttpsServer(seed + " base")
	if err != nil {
		return nil, err
	}
	self := &FakeBase{
		settings: settings,
		clock:    clock,
		seed:     seed,
		chainId:  chainId,
		https:    https,
		sources:  map[FakeBaseSourceKind]*FakeBaseSource{},
		genesis:  &fakeBaseState{accounts: map[FakeEvmAddress]*fakeBaseAccount{}, used: map[FakeEvmAddress]map[[32]byte]bool{}},
	}
	copy(self.usdc[:], fakeBytes(seed, "base usdc contract", 20))
	self.genesis.account(self.usdc).code = fakeBytes(seed, "base usdc code", 64)
	genesis := &fakeBaseBlock{number: 0, timestamp: uint64(clock.Now().Unix())}
	genesis.hash = self.blockHashWithLock(genesis)
	self.blocks = []*fakeBaseBlock{genesis}
	self.latest = self.genesis.clone()
	for kind, host := range map[FakeBaseSourceKind]string{FakeBaseCdp: FakeBaseCdpHost, FakeBaseAlchemy: FakeBaseAlchemyHost} {
		source := &FakeBaseSource{base: self, kind: kind, host: host, key: hex.EncodeToString(fakeBytes(seed, "base source key "+string(kind), 12)), disagreements: map[uint64][32]byte{}}
		switch kind {
		case FakeBaseCdp:
			source.path = "/rpc/v1/base/" + source.key
			source.logsRangeMax = settings.CdpLogsBlockRangeMaxCount
		case FakeBaseAlchemy:
			source.path = "/v2/" + source.key
			source.logsRangeMax = settings.AlchemyLogsBlockRangeMaxCount
		}
		self.sources[kind] = source
		https.handle(host, http.HandlerFunc(source.serveHttp))
	}
	return self, nil
}

func (self *FakeBase) Close() {
	self.https.close()
}

// A client that reaches the sources alone and trusts their test authority.
func (self *FakeBase) HttpClient() *http.Client {
	return self.https.httpClient()
}

// Dials the listener for a source's host, on any port; ErrFakeHostUnserved otherwise.
func (self *FakeBase) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	return self.https.dialContext(ctx, network, address)
}

func (self *FakeBase) RootCAs() *x509.CertPool {
	return self.https.authority.rootPool
}

func (self *FakeBase) ChainId() uint64 {
	return self.chainId
}

// The chain's CAIP-2 id, eip155:<chain id>.
func (self *FakeBase) Network() string {
	return "eip155:" + strconv.FormatUint(self.chainId, 10)
}

// The token's contract.
func (self *FakeBase) Usdc() FakeEvmAddress {
	return self.usdc
}

// The token's EIP-712 domain.
func (self *FakeBase) UsdcDomain() *FakeEip712Domain {
	return &FakeEip712Domain{Name: FakeBaseUsdcName, Version: FakeBaseUsdcVersion, ChainId: self.chainId, VerifyingContract: self.usdc}
}

// One of the two sources.
func (self *FakeBase) Source(kind FakeBaseSourceKind) *FakeBaseSource {
	return self.sources[kind]
}

// A block's hash: of the seed, its number, its parent's hash and the count of blocks ever made.
func (self *FakeBase) blockHashWithLock(block *fakeBaseBlock) [32]byte {
	self.blockCount += 1
	return fakeKeccak([]byte("computetest base block "+self.seed), fakeEvmWordUint(block.number), block.parentHash[:], fakeEvmWordUint(self.blockCount))
}

// Replays the state from the genesis allocation through block number, applying each transaction again: its status and
// logs as they come out there.
func (self *FakeBase) replayWithLock(number uint64) *fakeBaseState {
	state := self.genesis.clone()
	for _, block := range self.blocks[1 : number+1] {
		for index, tx := range block.txs {
			self.applyWithLock(state, block, index, tx)
		}
	}
	return state
}

// Applies tx in block to state, FiatToken's checks first: a reverted transaction still counts for its sender.
func (self *FakeBase) applyWithLock(state *fakeBaseState, block *fakeBaseBlock, index int, tx *fakeBaseTx) error {
	sender := state.account(tx.sender)
	tx.senderNonce = sender.count
	sender.count += 1
	tx.status = false
	tx.logs = nil
	logIndex := 0
	for _, earlier := range block.txs[:index] {
		logIndex += len(earlier.logs)
	}
	addLog := func(topics [][32]byte, data []byte) {
		tx.logs = append(tx.logs, &FakeBaseLog{
			Address:     self.usdc,
			Topics:      topics,
			Data:        data,
			BlockNumber: block.number,
			BlockHash:   block.hash,
			TxHash:      tx.hash,
			TxIndex:     index,
			LogIndex:    logIndex,
		})
		logIndex += 1
	}
	topicOf := func(address FakeEvmAddress) [32]byte {
		var topic [32]byte
		copy(topic[12:], address[:])
		return topic
	}
	switch tx.kind {
	case fakeBaseTransferWithAuthorization:
		auth := tx.auth
		signer, err := FakeRecoverEvmSigner(FakeTransferWithAuthorizationDigest(self.UsdcDomain(), auth), tx.signature)
		switch {
		case err != nil || signer != auth.From:
			return fmt.Errorf("%w: FiatTokenV2: invalid signature", ErrFakeBaseReverted)
		case block.timestamp <= auth.ValidAfter:
			return fmt.Errorf("%w: FiatTokenV2: authorization is not yet valid", ErrFakeBaseReverted)
		case block.timestamp >= auth.ValidBefore:
			return fmt.Errorf("%w: FiatTokenV2: authorization is expired", ErrFakeBaseReverted)
		case state.used[auth.From][auth.Nonce]:
			return fmt.Errorf("%w: FiatTokenV2: authorization is used or canceled", ErrFakeBaseReverted)
		case state.account(auth.From).usdc.Cmp(auth.Value) < 0:
			return fmt.Errorf("%w: ERC20: transfer amount exceeds balance", ErrFakeBaseReverted)
		}
		if state.used[auth.From] == nil {
			state.used[auth.From] = map[[32]byte]bool{}
		}
		state.used[auth.From][auth.Nonce] = true
		state.account(auth.From).usdc.Sub(state.account(auth.From).usdc, auth.Value)
		state.account(auth.To).usdc.Add(state.account(auth.To).usdc, auth.Value)
		addLog([][32]byte{fakeAuthorizationUsedTopic, topicOf(auth.From), auth.Nonce}, nil)
		addLog([][32]byte{fakeTransferTopic, topicOf(auth.From), topicOf(auth.To)}, fakeEvmWordInt(auth.Value))
	case fakeBaseTransfer:
		if state.account(tx.from).usdc.Cmp(tx.value) < 0 {
			return fmt.Errorf("%w: ERC20: transfer amount exceeds balance", ErrFakeBaseReverted)
		}
		state.account(tx.from).usdc.Sub(state.account(tx.from).usdc, tx.value)
		state.account(tx.to).usdc.Add(state.account(tx.to).usdc, tx.value)
		addLog([][32]byte{fakeTransferTopic, topicOf(tx.from), topicOf(tx.to)}, fakeEvmWordInt(tx.value))
	}
	tx.status = true
	return nil
}

// Mines tx into a new block at the clock's time, or refuses it as a node would refuse one that reverts.
func (self *FakeBase) mineWithLock(tx *fakeBaseTx) (*FakeBaseReceipt, error) {
	parent := self.blocks[len(self.blocks)-1]
	block := &fakeBaseBlock{number: parent.number + 1, parentHash: parent.hash, timestamp: self.nextTimestampWithLock(parent)}
	block.hash = self.blockHashWithLock(block)
	self.txCount += 1
	tx.hash = fakeKeccak([]byte("computetest base tx "+self.seed), fakeEvmWordUint(self.txCount))
	block.txs = []*fakeBaseTx{tx}
	trial := self.latest.clone()
	if err := self.applyWithLock(trial, block, 0, tx); err != nil {
		return nil, err
	}
	self.blocks = append(self.blocks, block)
	self.latest = trial
	return fakeBaseReceiptOf(block, tx), nil
}

func (self *FakeBase) nextTimestampWithLock(parent *fakeBaseBlock) uint64 {
	interval := uint64(self.settings.BlockInterval / time.Second)
	if interval < 1 {
		interval = 1
	}
	return max(parent.timestamp+interval, uint64(self.clock.Now().Unix()))
}

func fakeBaseReceiptOf(block *fakeBaseBlock, tx *fakeBaseTx) *FakeBaseReceipt {
	receipt := &FakeBaseReceipt{TxHash: tx.hash, BlockNumber: block.number, BlockHash: block.hash, From: tx.sender, Status: tx.status}
	for _, log := range tx.logs {
		logClone := *log
		receipt.Logs = append(receipt.Logs, &logClone)
	}
	return receipt
}

// Submits USDC's transferWithAuthorization from sender, the facilitator or anyone (out of band), mined at once into a
// block of its own; ErrFakeBaseReverted for one FiatToken would revert, which is not mined.
func (self *FakeBase) TransferWithAuthorization(sender FakeEvmAddress, auth *FakeTransferAuthorization, signature []byte) (*FakeBaseReceipt, error) {
	if auth == nil || auth.Value == nil || auth.Value.Sign() < 0 || auth.Value.BitLen() > 256 {
		return nil, fmt.Errorf("%w: an authorization's value", ErrFakeEvmMalformed)
	}
	authClone := *auth
	authClone.Value = new(big.Int).Set(auth.Value)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.mineWithLock(&fakeBaseTx{sender: sender, kind: fakeBaseTransferWithAuthorization, auth: &authClone, signature: slices.Clone(signature)})
}

// A holder's own transfer of USDC: a Transfer that settles no authorization.
func (self *FakeBase) Transfer(from FakeEvmAddress, to FakeEvmAddress, value *big.Int) (*FakeBaseReceipt, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.mineWithLock(&fakeBaseTx{sender: from, kind: fakeBaseTransfer, from: from, to: to, value: new(big.Int).Set(value)})
}

// Mines count empty blocks.
func (self *FakeBase) Mine(count int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for range count {
		parent := self.blocks[len(self.blocks)-1]
		block := &fakeBaseBlock{number: parent.number + 1, parentHash: parent.hash, timestamp: self.nextTimestampWithLock(parent)}
		block.hash = self.blockHashWithLock(block)
		self.blocks = append(self.blocks, block)
	}
}

// Moves the finalized head to number, the safe head with it where it was below; never past the latest or back.
func (self *FakeBase) Finalize(number uint64) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if number >= uint64(len(self.blocks)) || number < self.finalized {
		return fmt.Errorf("%w: finalized %d of %d", ErrFakeBaseHead, number, len(self.blocks)-1)
	}
	self.finalized = number
	self.safe = max(self.safe, number)
	return nil
}

// Moves the safe head to number, at or above the finalized head and at or below the latest.
func (self *FakeBase) SetSafe(number uint64) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if number >= uint64(len(self.blocks)) || number < self.finalized {
		return fmt.Errorf("%w: safe %d", ErrFakeBaseHead, number)
	}
	self.safe = number
	return nil
}

// The latest, safe and finalized heads' numbers.
func (self *FakeBase) Heads() (uint64, uint64, uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return uint64(len(self.blocks) - 1), self.safe, self.finalized
}

// A block's hash on the chain, or false past the latest.
func (self *FakeBase) BlockHash(number uint64) ([32]byte, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if number >= uint64(len(self.blocks)) {
		return [32]byte{}, false
	}
	return self.blocks[number].hash, true
}

// Replaces the latest depth blocks with as many new ones, of other hashes: keep re-includes their transactions in
// the new blocks, in order, each applied again there; otherwise they are dropped and what they did is undone. A
// reorg reaching the safe head is refused.
func (self *FakeBase) Reorg(depth int, keep bool) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	latest := uint64(len(self.blocks) - 1)
	if depth < 1 || uint64(depth) > latest || latest-uint64(depth) < self.safe {
		return fmt.Errorf("%w: a reorg of %d blocks with the safe head at %d of %d", ErrFakeBaseHead, depth, self.safe, latest)
	}
	dropped := self.blocks[latest-uint64(depth)+1:]
	self.blocks = slices.Clone(self.blocks[:latest-uint64(depth)+1])
	for _, old := range dropped {
		parent := self.blocks[len(self.blocks)-1]
		block := &fakeBaseBlock{number: old.number, parentHash: parent.hash, timestamp: old.timestamp}
		block.hash = self.blockHashWithLock(block)
		if keep {
			for _, tx := range old.txs {
				block.txs = append(block.txs, tx)
			}
		}
		self.blocks = append(self.blocks, block)
	}
	self.latest = self.replayWithLock(uint64(len(self.blocks) - 1))
	return nil
}

// Sets a holder's USDC in the genesis allocation and from then on.
func (self *FakeBase) Fund(holder FakeEvmAddress, value *big.Int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.genesis.account(holder).usdc = new(big.Int).Set(value)
	self.latest = self.replayWithLock(uint64(len(self.blocks) - 1))
}

// Sets an account's ETH balance, code or transaction count in the genesis allocation and from then on, as the payee
// screen reads them.
func (self *FakeBase) SetEthBalance(holder FakeEvmAddress, wei *big.Int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.genesis.account(holder).eth = new(big.Int).Set(wei)
	self.latest = self.replayWithLock(uint64(len(self.blocks) - 1))
}

func (self *FakeBase) SetCode(holder FakeEvmAddress, code []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.genesis.account(holder).code = slices.Clone(code)
	self.latest = self.replayWithLock(uint64(len(self.blocks) - 1))
}

func (self *FakeBase) SetTransactionCount(holder FakeEvmAddress, count uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.genesis.account(holder).count = count
	self.latest = self.replayWithLock(uint64(len(self.blocks) - 1))
}

// A holder's USDC at the latest block.
func (self *FakeBase) UsdcBalance(holder FakeEvmAddress) *big.Int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return new(big.Int).Set(self.latest.account(holder).usdc)
}

// Whether an authorizer's nonce is used at the latest block.
func (self *FakeBase) AuthorizationUsed(authorizer FakeEvmAddress, nonce [32]byte) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.latest.used[authorizer][nonce]
}

// The logs of the chain's blocks from through to, in order.
func (self *FakeBase) Logs(from uint64, to uint64) []*FakeBaseLog {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	logs := []*FakeBaseLog{}
	for _, block := range self.blocks {
		if block.number < from || block.number > to {
			continue
		}
		for _, tx := range block.txs {
			for _, log := range tx.logs {
				logClone := *log
				logs = append(logs, &logClone)
			}
		}
	}
	return logs
}

// One JSON-RPC source of the chain: its view, and whether it answers.
type FakeBaseSource struct {
	base         *FakeBase
	kind         FakeBaseSourceKind
	host         string
	key          string
	path         string
	logsRangeMax uint64

	// the chain's lock guards these
	lag           uint64
	down          bool
	disagreements map[uint64][32]byte
	methods       []string
}

// The source's URL, its key in its path as the provider's are.
func (self *FakeBaseSource) Url() string {
	return "https://" + self.host + self.path
}

// The source sees the chain only to lag blocks below its latest, its safe and finalized heads no higher.
func (self *FakeBaseSource) SetLag(lag uint64) {
	self.base.stateLock.Lock()
	defer self.base.stateLock.Unlock()
	self.lag = lag
}

// The source answers every call with an internal error while down.
func (self *FakeBaseSource) SetDown(down bool) {
	self.base.stateLock.Lock()
	defer self.base.stateLock.Unlock()
	self.down = down
}

// The source reports another hash for a block: in the block, in its child's parent hash and in its logs, the two
// sources disagreeing there until Agree.
func (self *FakeBaseSource) Disagree(number uint64) {
	self.base.stateLock.Lock()
	defer self.base.stateLock.Unlock()
	self.disagreements[number] = fakeKeccak([]byte("computetest base disagreement "+self.base.seed+" "+string(self.kind)), fakeEvmWordUint(number))
}

func (self *FakeBaseSource) Agree() {
	self.base.stateLock.Lock()
	defer self.base.stateLock.Unlock()
	clear(self.disagreements)
}

// The methods called, in order, a batch's each.
func (self *FakeBaseSource) Methods() []string {
	self.base.stateLock.Lock()
	defer self.base.stateLock.Unlock()
	return slices.Clone(self.methods)
}

// A JSON-RPC error.
type fakeRpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (self *fakeRpcError) Error() string {
	return self.Message
}

type fakeRpcRequest struct {
	JsonRpc string            `json:"jsonrpc"`
	Id      json.RawMessage   `json:"id"`
	Method  string            `json:"method"`
	Params  []json.RawMessage `json:"params"`
}

type fakeRpcResponse struct {
	JsonRpc string          `json:"jsonrpc"`
	Id      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *fakeRpcError   `json:"error,omitempty"`
}

func (self *FakeBaseSource) serveHttp(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != self.path {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(&fakeRpcResponse{JsonRpc: "2.0", Id: json.RawMessage("null"), Error: &fakeRpcError{Code: -32600, Message: "Must be authenticated!"}})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, self.base.settings.RequestBodyMaxByteCount))
	if err != nil {
		http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
		return
	}
	trimmed := strings.TrimSpace(string(body))
	var answer any
	if strings.HasPrefix(trimmed, "[") {
		var requests []*fakeRpcRequest
		if err := json.Unmarshal(body, &requests); err != nil || len(requests) == 0 || len(requests) > self.base.settings.BatchMaxCount {
			answer = &fakeRpcResponse{JsonRpc: "2.0", Id: json.RawMessage("null"), Error: &fakeRpcError{Code: -32600, Message: "invalid batch"}}
		} else {
			responses := []*fakeRpcResponse{}
			for _, request := range requests {
				responses = append(responses, self.call(request))
			}
			answer = responses
		}
	} else {
		var request fakeRpcRequest
		if err := json.Unmarshal(body, &request); err != nil {
			answer = &fakeRpcResponse{JsonRpc: "2.0", Id: json.RawMessage("null"), Error: &fakeRpcError{Code: -32700, Message: "parse error"}}
		} else {
			answer = self.call(&request)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(answer)
}

func (self *FakeBaseSource) call(request *fakeRpcRequest) *fakeRpcResponse {
	response := &fakeRpcResponse{JsonRpc: "2.0", Id: request.Id}
	if len(response.Id) == 0 {
		response.Id = json.RawMessage("null")
	}
	self.base.stateLock.Lock()
	defer self.base.stateLock.Unlock()
	self.methods = append(self.methods, request.Method)
	if self.down {
		response.Error = &fakeRpcError{Code: -32603, Message: "internal error"}
		return response
	}
	result, err := self.callWithLock(request.Method, request.Params)
	if err != nil {
		var rpcErr *fakeRpcError
		if !errors.As(err, &rpcErr) {
			rpcErr = &fakeRpcError{Code: -32602, Message: err.Error()}
		}
		response.Error = rpcErr
		return response
	}
	response.Result = result
	return response
}

func fakeRpcHexUint(value uint64) string {
	return "0x" + strconv.FormatUint(value, 16)
}

func fakeRpcHexBig(value *big.Int) string {
	return "0x" + value.Text(16)
}

func fakeRpcHex(value []byte) string {
	return "0x" + hex.EncodeToString(value)
}

func fakeRpcParseUint(value string) (uint64, error) {
	digits, ok := strings.CutPrefix(value, "0x")
	if !ok || digits == "" {
		return 0, fmt.Errorf("a quantity %q", value)
	}
	return strconv.ParseUint(digits, 16, 64)
}

// The source's view of its heads.
func (self *FakeBaseSource) headsWithLock() (uint64, uint64, uint64) {
	latest := uint64(len(self.base.blocks) - 1)
	visible := latest
	if self.lag > latest {
		visible = 0
	} else {
		visible -= self.lag
	}
	return visible, min(self.base.safe, visible), min(self.base.finalized, visible)
}

// A block parameter: a tag, a number, or an EIP-1898 object by hash or number; false past the source's view.
func (self *FakeBaseSource) blockNumberWithLock(raw json.RawMessage) (uint64, bool, error) {
	latest, safe, finalized := self.headsWithLock()
	if len(raw) == 0 {
		return latest, true, nil
	}
	var tag string
	if err := json.Unmarshal(raw, &tag); err != nil {
		var object struct {
			BlockHash   string `json:"blockHash"`
			BlockNumber string `json:"blockNumber"`
		}
		if err := json.Unmarshal(raw, &object); err != nil {
			return 0, false, fmt.Errorf("a block parameter")
		}
		if object.BlockHash != "" {
			block, ok := self.blockByHashWithLock(object.BlockHash)
			if !ok {
				return 0, false, &fakeRpcError{Code: -32000, Message: "header not found"}
			}
			return block.number, true, nil
		}
		tag = object.BlockNumber
	}
	switch tag {
	case "latest", "pending":
		return latest, true, nil
	case "safe":
		return safe, true, nil
	case "finalized":
		return finalized, true, nil
	case "earliest":
		return 0, true, nil
	}
	number, err := fakeRpcParseUint(tag)
	if err != nil {
		return 0, false, err
	}
	return number, number <= latest, nil
}

// A block's hash as this source reports it.
func (self *FakeBaseSource) hashWithLock(number uint64) [32]byte {
	if hash, ok := self.disagreements[number]; ok {
		return hash
	}
	return self.base.blocks[number].hash
}

func (self *FakeBaseSource) blockByHashWithLock(value string) (*fakeBaseBlock, bool) {
	raw, err := fakeEvmParseBytes(value, 32)
	if err != nil {
		return nil, false
	}
	latest, _, _ := self.headsWithLock()
	for _, block := range self.base.blocks[:latest+1] {
		hash := self.hashWithLock(block.number)
		if string(hash[:]) == string(raw) {
			return block, true
		}
	}
	return nil, false
}

func (self *FakeBaseSource) renderBlockWithLock(block *fakeBaseBlock, fullTransactions bool) map[string]any {
	parentHash := block.parentHash
	if block.number > 0 {
		parentHash = self.hashWithLock(block.number - 1)
	}
	hash := self.hashWithLock(block.number)
	transactions := []any{}
	for index, tx := range block.txs {
		if fullTransactions {
			transactions = append(transactions, self.renderTxWithLock(block, index, tx))
		} else {
			transactions = append(transactions, fakeRpcHex(tx.hash[:]))
		}
	}
	zero32 := fakeRpcHex(make([]byte, 32))
	return map[string]any{
		"number":           fakeRpcHexUint(block.number),
		"hash":             fakeRpcHex(hash[:]),
		"parentHash":       fakeRpcHex(parentHash[:]),
		"timestamp":        fakeRpcHexUint(block.timestamp),
		"transactions":     transactions,
		"miner":            FakeEvmAddress{}.Hex(),
		"gasLimit":         fakeRpcHexUint(30000000),
		"gasUsed":          fakeRpcHexUint(uint64(len(block.txs)) * 60000),
		"baseFeePerGas":    fakeRpcHexUint(1000000),
		"difficulty":       "0x0",
		"nonce":            "0x0000000000000000",
		"extraData":        "0x",
		"logsBloom":        fakeRpcHex(make([]byte, 256)),
		"stateRoot":        zero32,
		"receiptsRoot":     zero32,
		"transactionsRoot": zero32,
		"sha3Uncles":       zero32,
		"mixHash":          zero32,
		"uncles":           []any{},
		"size":             fakeRpcHexUint(1000),
	}
}

// A transferWithAuthorization's or transfer's calldata, as the transaction's input.
func fakeBaseCalldata(tx *fakeBaseTx) []byte {
	if tx.kind == fakeBaseTransfer {
		return slices.Concat(fakeTransferSelector[:4], fakeEvmWordAddress(tx.to), fakeEvmWordInt(tx.value))
	}
	auth := tx.auth
	v := uint64(0)
	if len(tx.signature) == 65 {
		v = uint64(tx.signature[64])
	}
	r := make([]byte, 32)
	s := make([]byte, 32)
	if len(tx.signature) == 65 {
		copy(r, tx.signature[:32])
		copy(s, tx.signature[32:64])
	}
	return slices.Concat(fakeTransferWithAuthSelector[:4], fakeEvmWordAddress(auth.From), fakeEvmWordAddress(auth.To), fakeEvmWordInt(auth.Value),
		fakeEvmWordUint(auth.ValidAfter), fakeEvmWordUint(auth.ValidBefore), auth.Nonce[:], fakeEvmWordUint(v), r, s)
}

func (self *FakeBaseSource) renderTxWithLock(block *fakeBaseBlock, index int, tx *fakeBaseTx) map[string]any {
	hash := self.hashWithLock(block.number)
	return map[string]any{
		"hash":             fakeRpcHex(tx.hash[:]),
		"blockNumber":      fakeRpcHexUint(block.number),
		"blockHash":        fakeRpcHex(hash[:]),
		"transactionIndex": fakeRpcHexUint(uint64(index)),
		"from":             tx.sender.Hex(),
		"to":               self.base.usdc.Hex(),
		"input":            fakeRpcHex(fakeBaseCalldata(tx)),
		"value":            "0x0",
		"nonce":            fakeRpcHexUint(tx.senderNonce),
		"gas":              fakeRpcHexUint(100000),
		"type":             "0x2",
		"chainId":          fakeRpcHexUint(self.base.chainId),
	}
}

func (self *FakeBaseSource) renderLogWithLock(log *FakeBaseLog) map[string]any {
	topics := []string{}
	for _, topic := range log.Topics {
		topics = append(topics, fakeRpcHex(topic[:]))
	}
	hash := self.hashWithLock(log.BlockNumber)
	return map[string]any{
		"address":          log.Address.Hex(),
		"topics":           topics,
		"data":             fakeRpcHex(log.Data),
		"blockNumber":      fakeRpcHexUint(log.BlockNumber),
		"blockHash":        fakeRpcHex(hash[:]),
		"transactionHash":  fakeRpcHex(log.TxHash[:]),
		"transactionIndex": fakeRpcHexUint(uint64(log.TxIndex)),
		"logIndex":         fakeRpcHexUint(uint64(log.LogIndex)),
		"removed":          false,
	}
}

// The state at a block of the source's view.
func (self *FakeBaseSource) stateWithLock(raw json.RawMessage) (*fakeBaseState, error) {
	number, ok, err := self.blockNumberWithLock(raw)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, &fakeRpcError{Code: -32000, Message: "header not found"}
	}
	if number == uint64(len(self.base.blocks)-1) {
		return self.base.latest, nil
	}
	return self.base.replayWithLock(number), nil
}

// A transaction by its hash on the source's view, its block and index.
func (self *FakeBaseSource) txWithLock(raw json.RawMessage) (*fakeBaseBlock, int, *fakeBaseTx) {
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return nil, 0, nil
	}
	hash, err := fakeEvmParseBytes(value, 32)
	if err != nil {
		return nil, 0, nil
	}
	latest, _, _ := self.headsWithLock()
	for _, block := range self.base.blocks[:latest+1] {
		for index, tx := range block.txs {
			if string(tx.hash[:]) == string(hash) {
				return block, index, tx
			}
		}
	}
	return nil, 0, nil
}

// One call, its params as JSON-RPC carries them.
func (self *FakeBaseSource) callWithLock(method string, params []json.RawMessage) (any, error) {
	param := func(index int) json.RawMessage {
		if index < len(params) {
			return params[index]
		}
		return nil
	}
	addressParam := func(index int) (FakeEvmAddress, error) {
		var value string
		if err := json.Unmarshal(param(index), &value); err != nil {
			return FakeEvmAddress{}, fmt.Errorf("an address")
		}
		return ParseFakeEvmAddress(value)
	}
	switch method {
	case "eth_chainId":
		return fakeRpcHexUint(self.base.chainId), nil
	case "net_version":
		return strconv.FormatUint(self.base.chainId, 10), nil
	case "eth_blockNumber":
		latest, _, _ := self.headsWithLock()
		return fakeRpcHexUint(latest), nil
	case "eth_getBlockByNumber":
		number, ok, err := self.blockNumberWithLock(param(0))
		if err != nil {
			return nil, err
		}
		if !ok {
			return json.RawMessage("null"), nil
		}
		var full bool
		json.Unmarshal(param(1), &full)
		return self.renderBlockWithLock(self.base.blocks[number], full), nil
	case "eth_getBlockByHash":
		var value string
		json.Unmarshal(param(0), &value)
		block, ok := self.blockByHashWithLock(value)
		if !ok {
			return json.RawMessage("null"), nil
		}
		var full bool
		json.Unmarshal(param(1), &full)
		return self.renderBlockWithLock(block, full), nil
	case "eth_getLogs":
		return self.logsWithLock(param(0))
	case "eth_getCode":
		address, err := addressParam(0)
		if err != nil {
			return nil, err
		}
		state, err := self.stateWithLock(param(1))
		if err != nil {
			return nil, err
		}
		return fakeRpcHex(state.account(address).code), nil
	case "eth_getTransactionCount":
		address, err := addressParam(0)
		if err != nil {
			return nil, err
		}
		state, err := self.stateWithLock(param(1))
		if err != nil {
			return nil, err
		}
		return fakeRpcHexUint(state.account(address).count), nil
	case "eth_getBalance":
		address, err := addressParam(0)
		if err != nil {
			return nil, err
		}
		state, err := self.stateWithLock(param(1))
		if err != nil {
			return nil, err
		}
		return fakeRpcHexBig(state.account(address).eth), nil
	case "eth_call":
		return self.ethCallWithLock(param(0), param(1))
	case "eth_getTransactionByHash":
		block, index, tx := self.txWithLock(param(0))
		if tx == nil {
			return json.RawMessage("null"), nil
		}
		return self.renderTxWithLock(block, index, tx), nil
	case "eth_getTransactionReceipt":
		block, index, tx := self.txWithLock(param(0))
		if tx == nil {
			return json.RawMessage("null"), nil
		}
		hash := self.hashWithLock(block.number)
		logs := []any{}
		for _, log := range tx.logs {
			logs = append(logs, self.renderLogWithLock(log))
		}
		status := "0x0"
		if tx.status {
			status = "0x1"
		}
		return map[string]any{
			"transactionHash":   fakeRpcHex(tx.hash[:]),
			"blockNumber":       fakeRpcHexUint(block.number),
			"blockHash":         fakeRpcHex(hash[:]),
			"transactionIndex":  fakeRpcHexUint(uint64(index)),
			"from":              tx.sender.Hex(),
			"to":                self.base.usdc.Hex(),
			"status":            status,
			"logs":              logs,
			"gasUsed":           fakeRpcHexUint(60000),
			"cumulativeGasUsed": fakeRpcHexUint(60000 * uint64(index+1)),
			"effectiveGasPrice": fakeRpcHexUint(1000000),
			"contractAddress":   nil,
			"logsBloom":         fakeRpcHex(make([]byte, 256)),
			"type":              "0x2",
		}, nil
	}
	return nil, &fakeRpcError{Code: -32601, Message: "the method " + method + " does not exist/is not available"}
}

// eth_call on the token: balanceOf, authorizationState and DOMAIN_SEPARATOR; an account with no code answers 0x, and
// anything else reverts.
func (self *FakeBaseSource) ethCallWithLock(rawCall json.RawMessage, rawBlock json.RawMessage) (any, error) {
	var call struct {
		To    string `json:"to"`
		Data  string `json:"data"`
		Input string `json:"input"`
	}
	if err := json.Unmarshal(rawCall, &call); err != nil {
		return nil, fmt.Errorf("a call object")
	}
	to, err := ParseFakeEvmAddress(call.To)
	if err != nil {
		return nil, err
	}
	data := call.Data
	if data == "" {
		data = call.Input
	}
	input, err := hex.DecodeString(strings.TrimPrefix(data, "0x"))
	if err != nil || len(input) < 4 {
		return nil, &fakeRpcError{Code: 3, Message: "execution reverted"}
	}
	state, err := self.stateWithLock(rawBlock)
	if err != nil {
		return nil, err
	}
	if to != self.base.usdc {
		if len(state.account(to).code) == 0 {
			return "0x", nil
		}
		return nil, &fakeRpcError{Code: 3, Message: "execution reverted"}
	}
	selector := input[:4]
	arguments := input[4:]
	wordAddress := func(word []byte) FakeEvmAddress {
		var address FakeEvmAddress
		copy(address[:], word[12:32])
		return address
	}
	switch {
	case string(selector) == string(fakeBalanceOfSelector[:4]) && len(arguments) == 32:
		return fakeRpcHex(fakeEvmWordInt(state.account(wordAddress(arguments)).usdc)), nil
	case string(selector) == string(fakeAuthorizationStateSelector[:4]) && len(arguments) == 64:
		var nonce [32]byte
		copy(nonce[:], arguments[32:64])
		used := uint64(0)
		if state.used[wordAddress(arguments[:32])][nonce] {
			used = 1
		}
		return fakeRpcHex(fakeEvmWordUint(used)), nil
	case string(selector) == string(fakeDomainSeparatorSelector[:4]):
		separator := self.base.UsdcDomain().separator()
		return fakeRpcHex(separator[:]), nil
	}
	return nil, &fakeRpcError{Code: 3, Message: "execution reverted"}
}

// eth_getLogs over the source's view: by blockHash, or fromBlock to toBlock (each latest by default) within the
// source's cap; then address and topics, each topic null, one value or a list of values.
func (self *FakeBaseSource) logsWithLock(raw json.RawMessage) (any, error) {
	var filter struct {
		FromBlock json.RawMessage   `json:"fromBlock"`
		ToBlock   json.RawMessage   `json:"toBlock"`
		BlockHash string            `json:"blockHash"`
		Address   json.RawMessage   `json:"address"`
		Topics    []json.RawMessage `json:"topics"`
	}
	if err := json.Unmarshal(raw, &filter); err != nil {
		return nil, fmt.Errorf("a filter object")
	}
	var from, to uint64
	if filter.BlockHash != "" {
		if len(filter.FromBlock) > 0 || len(filter.ToBlock) > 0 {
			return nil, fmt.Errorf("blockHash with fromBlock or toBlock")
		}
		block, ok := self.blockByHashWithLock(filter.BlockHash)
		if !ok {
			return nil, &fakeRpcError{Code: -32000, Message: "unknown block"}
		}
		from, to = block.number, block.number
	} else {
		var err error
		var ok bool
		if from, ok, err = self.blockNumberWithLock(filter.FromBlock); err != nil {
			return nil, err
		} else if !ok {
			return []any{}, nil
		}
		latest, _, _ := self.headsWithLock()
		if to, ok, err = self.blockNumberWithLock(filter.ToBlock); err != nil {
			return nil, err
		} else if !ok {
			to = latest
		}
		if from > to {
			return []any{}, nil
		}
		if to-from+1 > self.logsRangeMax {
			return nil, &fakeRpcError{Code: -32602, Message: fmt.Sprintf("eth_getLogs is limited to a %d block range", self.logsRangeMax)}
		}
	}
	addresses := []FakeEvmAddress{}
	if len(filter.Address) > 0 && string(filter.Address) != "null" {
		values := []string{}
		var single string
		if json.Unmarshal(filter.Address, &single) == nil {
			values = append(values, single)
		} else if err := json.Unmarshal(filter.Address, &values); err != nil {
			return nil, fmt.Errorf("an address filter")
		}
		for _, value := range values {
			address, err := ParseFakeEvmAddress(value)
			if err != nil {
				return nil, err
			}
			addresses = append(addresses, address)
		}
	}
	topicSets := [][][32]byte{}
	for _, rawTopic := range filter.Topics {
		set := [][32]byte{}
		values := []string{}
		var single string
		switch {
		case string(rawTopic) == "null":
		case json.Unmarshal(rawTopic, &single) == nil:
			values = append(values, single)
		default:
			if err := json.Unmarshal(rawTopic, &values); err != nil {
				return nil, fmt.Errorf("a topic filter")
			}
		}
		for _, value := range values {
			topic, err := fakeEvmParseBytes(value, 32)
			if err != nil {
				return nil, err
			}
			set = append(set, [32]byte(topic))
		}
		topicSets = append(topicSets, set)
	}
	logs := []any{}
	for _, block := range self.base.blocks[from : to+1] {
		for _, tx := range block.txs {
			for _, log := range tx.logs {
				if len(addresses) > 0 && !slices.Contains(addresses, log.Address) {
					continue
				}
				matched := true
				for index, set := range topicSets {
					if len(set) == 0 {
						continue
					}
					if index >= len(log.Topics) || !slices.Contains(set, log.Topics[index]) {
						matched = false
						break
					}
				}
				if matched {
					logs = append(logs, self.renderLogWithLock(log))
				}
			}
		}
	}
	return logs, nil
}

// A 32-byte value as a big-endian integer, for a test reading a log's data.
func FakeBaseWordValue(word []byte) *big.Int {
	return new(big.Int).SetBytes(word)
}

// A nonce drawn from a seed and label, as a device draws one.
func FakeBaseNonce(seed string, label string) [32]byte {
	var nonce [32]byte
	copy(nonce[:], fakeBytes(seed, "base nonce "+label, 32))
	return nonce
}

// The time a block of the chain carries, for a test placing an authorization's window.
func (self *FakeBase) BlockTime(number uint64) (time.Time, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if number >= uint64(len(self.blocks)) {
		return time.Time{}, false
	}
	return time.Unix(int64(self.blocks[number].timestamp), 0).UTC(), true
}
