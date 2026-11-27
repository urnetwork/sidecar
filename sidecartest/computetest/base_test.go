package computetest

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

func newTestBase(t *testing.T, settings *FakeBaseSettings) (*FakeBase, *sidecartest.FakeClock) {
	t.Helper()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	base, err := NewFakeBase(&FakeBaseArgs{Settings: settings, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(base.Close)
	return base, clock
}

// One JSON-RPC call to a source: its result, or its error's code.
func testRpc(t *testing.T, base *FakeBase, kind FakeBaseSourceKind, method string, params ...any) (json.RawMessage, int) {
	t.Helper()
	if params == nil {
		params = []any{}
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		t.Fatal(err)
	}
	response, err := base.HttpClient().Post(base.Source(kind).Url(), "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var answer struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&answer); err != nil {
		t.Fatal(err)
	}
	if answer.Error != nil {
		return nil, answer.Error.Code
	}
	return answer.Result, 0
}

func testRpcBlock(t *testing.T, base *FakeBase, kind FakeBaseSourceKind, tag string) map[string]any {
	t.Helper()
	result, code := testRpc(t, base, kind, "eth_getBlockByNumber", tag, false)
	if code != 0 {
		t.Fatalf("%s's block %s: error %d", kind, tag, code)
	}
	var block map[string]any
	if err := json.Unmarshal(result, &block); err != nil {
		t.Fatal(err)
	}
	return block
}

// An authorization from payer to payee of value, valid a minute before now to two after, signed.
func testAuthorization(base *FakeBase, clock *sidecartest.FakeClock, payer *FakeEvmKey, payee FakeEvmAddress, value int64, nonceLabel string) (*FakeTransferAuthorization, []byte) {
	now := uint64(clock.Now().Unix())
	auth := &FakeTransferAuthorization{
		From:        payer.Address(),
		To:          payee,
		Value:       big.NewInt(value),
		ValidAfter:  now - 60,
		ValidBefore: now + 120,
		Nonce:       FakeBaseNonce("computetest", nonceLabel),
	}
	return auth, payer.SignTransferWithAuthorization(base.UsdcDomain(), auth)
}

func TestFakeEvmVectors(t *testing.T) {
	for name, want := range map[string]struct {
		got  [32]byte
		want string
	}{
		"the TransferWithAuthorization typehash Circle's FiatToken declares": {got: fakeTransferWithAuthorizationHash, want: "7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267"},
		"EIP-712's domain typehash": {got: fakeEip712DomainTypeHash, want: "8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f"},
		"ERC-20's Transfer topic":   {got: fakeTransferTopic, want: "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"},
	} {
		if hex.EncodeToString(want.got[:]) != want.want {
			t.Errorf("%s: %x", name, want.got)
		}
	}
	for name, want := range map[string]struct {
		got  [32]byte
		want string
	}{
		"balanceOf":                 {got: fakeBalanceOfSelector, want: "70a08231"},
		"authorizationState":        {got: fakeAuthorizationStateSelector, want: "e94a0102"},
		"transferWithAuthorization": {got: fakeTransferWithAuthSelector, want: "e3ee160e"},
	} {
		if hex.EncodeToString(want.got[:4]) != want.want {
			t.Errorf("%s's selector: %x", name, want.got[:4])
		}
	}
	// EIP-55's own test vector
	address, err := ParseFakeEvmAddress("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
	if err != nil || address.ChecksumHex() != "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed" {
		t.Errorf("EIP-55: %s, %v", address.ChecksumHex(), err)
	}
}

func TestFakeEvmRecoverRefusesMalleable(t *testing.T) {
	base, clock := newTestBase(t, nil)
	payer := NewFakeEvmKey("computetest", "test payer")
	auth, signature := testAuthorization(base, clock, payer, FakeEvmAddress{1}, 10000, "recover")
	digest := FakeTransferWithAuthorizationDigest(base.UsdcDomain(), auth)
	signer, err := FakeRecoverEvmSigner(digest, signature)
	if err != nil || signer != payer.Address() {
		t.Fatalf("recovered %s, %v", signer.Hex(), err)
	}
	if again := payer.SignTransferWithAuthorization(base.UsdcDomain(), auth); !bytes.Equal(again, signature) {
		t.Fatalf("signing is not deterministic")
	}
	for name, bad := range map[string][]byte{
		"the high-s twin": FakeEvmMalleate(signature),
		"v of 0":          append(append([]byte{}, signature[:64]...), 0),
		"v of 1":          append(append([]byte{}, signature[:64]...), 1),
		"v of 29":         append(append([]byte{}, signature[:64]...), 29),
		"64 bytes":        signature[:64],
	} {
		if _, err := FakeRecoverEvmSigner(digest, bad); !errors.Is(err, ErrFakeEvmSignature) {
			t.Errorf("%s recovered: %v", name, err)
		}
	}
}

func TestFakeBaseFinalizesAndReorgs(t *testing.T) {
	base, clock := newTestBase(t, nil)
	payer := NewFakeEvmKey("computetest", "test payer")
	facilitator := NewFakeEvmKey("computetest", "test facilitator")
	payee := FakeEvmAddress{0xfe, 0x01}
	base.Fund(payer.Address(), big.NewInt(1000000))
	base.Mine(1)
	if err := base.Finalize(1); err != nil {
		t.Fatal(err)
	}
	auth, signature := testAuthorization(base, clock, payer, payee, 10000, "reorg")
	receipt, err := base.TransferWithAuthorization(facilitator.Address(), auth, signature)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.BlockNumber != 2 || receipt.From != facilitator.Address() || len(receipt.Logs) != 2 ||
		receipt.Logs[0].Topics[0] != fakeAuthorizationUsedTopic || receipt.Logs[1].Topics[0] != fakeTransferTopic {
		t.Fatalf("receipt %+v", receipt)
	}
	base.Mine(2)
	if block := testRpcBlock(t, base, FakeBaseCdp, "finalized"); block["number"] != "0x1" {
		t.Fatalf("the finalized head is %v", block["number"])
	}
	if block := testRpcBlock(t, base, FakeBaseCdp, "latest"); block["number"] != "0x4" {
		t.Fatalf("the latest head is %v", block["number"])
	}
	settledHash, _ := base.BlockHash(2)
	// a reorg of the unsafe head that drops the settlement undoes it
	if err := base.Reorg(3, false); err != nil {
		t.Fatal(err)
	}
	if base.AuthorizationUsed(payer.Address(), auth.Nonce) || base.UsdcBalance(payee).Sign() != 0 || base.UsdcBalance(payer.Address()).Int64() != 1000000 {
		t.Fatalf("the dropped settlement still stands")
	}
	if hash, _ := base.BlockHash(2); hash == settledHash {
		t.Fatalf("the reorg kept block 2's hash")
	}
	logs, code := testRpc(t, base, FakeBaseAlchemy, "eth_getLogs", map[string]any{"fromBlock": "0x0", "toBlock": "latest", "address": base.Usdc().Hex()})
	if code != 0 || string(logs) != "[]" {
		t.Fatalf("logs after the reorg: %s (%d)", logs, code)
	}
	// settled again, then a reorg that keeps it: the same transaction in a block of another hash
	receipt, err = base.TransferWithAuthorization(facilitator.Address(), auth, signature)
	if err != nil {
		t.Fatal(err)
	}
	if err := base.Reorg(1, true); err != nil {
		t.Fatal(err)
	}
	if !base.AuthorizationUsed(payer.Address(), auth.Nonce) || base.UsdcBalance(payee).Int64() != 10000 {
		t.Fatalf("the kept settlement does not stand")
	}
	kept := base.Logs(receipt.BlockNumber, receipt.BlockNumber)
	if len(kept) != 2 || kept[0].TxHash != receipt.TxHash || kept[0].BlockHash == receipt.BlockHash {
		t.Fatalf("the kept settlement's logs %+v", kept)
	}
	// the nonce settles once
	if _, err := base.TransferWithAuthorization(facilitator.Address(), auth, signature); !errors.Is(err, ErrFakeBaseReverted) {
		t.Fatalf("a used nonce settled again: %v", err)
	}
	// a reorg reaching the safe head is refused, and so is moving the finalized head back
	latest, _, _ := base.Heads()
	if err := base.SetSafe(latest); err != nil {
		t.Fatal(err)
	}
	if err := base.Reorg(1, false); !errors.Is(err, ErrFakeBaseHead) {
		t.Fatalf("a reorg of the safe head answered %v", err)
	}
	if err := base.Finalize(0); !errors.Is(err, ErrFakeBaseHead) {
		t.Fatalf("finalizing back answered %v", err)
	}
	// an authorization whose window has closed reverts and is not mined
	late, lateSignature := testAuthorization(base, clock, payer, payee, 10000, "late")
	late.ValidBefore = late.ValidAfter + 1
	lateSignature = payer.SignTransferWithAuthorization(base.UsdcDomain(), late)
	if _, err := base.TransferWithAuthorization(facilitator.Address(), late, lateSignature); !errors.Is(err, ErrFakeBaseReverted) {
		t.Fatalf("an expired authorization answered %v", err)
	}
	if after, _, _ := base.Heads(); after != latest {
		t.Fatalf("a reverted transaction was mined")
	}
}

func TestFakeBaseSourcesDisagree(t *testing.T) {
	settings := DefaultFakeBaseSettings()
	settings.CdpLogsBlockRangeMaxCount = 4
	base, _ := newTestBase(t, settings)
	base.Mine(6)
	if err := base.Finalize(3); err != nil {
		t.Fatal(err)
	}
	cdp := testRpcBlock(t, base, FakeBaseCdp, "0x2")
	alchemy := testRpcBlock(t, base, FakeBaseAlchemy, "0x2")
	if cdp["hash"] != alchemy["hash"] {
		t.Fatalf("the sources disagree before any disagreement")
	}
	base.Source(FakeBaseAlchemy).Disagree(2)
	alchemy = testRpcBlock(t, base, FakeBaseAlchemy, "0x2")
	child := testRpcBlock(t, base, FakeBaseAlchemy, "0x3")
	if cdp["hash"] == alchemy["hash"] || child["parentHash"] != alchemy["hash"] {
		t.Fatalf("the disagreement is not reported: %v %v %v", cdp["hash"], alchemy["hash"], child["parentHash"])
	}
	if testRpcBlock(t, base, FakeBaseCdp, "0x3")["parentHash"] != cdp["hash"] {
		t.Fatalf("the agreeing source moved too")
	}
	base.Source(FakeBaseAlchemy).Agree()
	if testRpcBlock(t, base, FakeBaseAlchemy, "0x2")["hash"] != cdp["hash"] {
		t.Fatalf("the sources still disagree")
	}
	// a lagging source sees an older head, and its finalized head no higher
	base.Source(FakeBaseCdp).SetLag(5)
	if number, _ := testRpc(t, base, FakeBaseCdp, "eth_blockNumber"); string(number) != `"0x1"` {
		t.Fatalf("the lagging source's head is %s", number)
	}
	if testRpcBlock(t, base, FakeBaseCdp, "finalized")["number"] != "0x1" {
		t.Fatalf("the lagging source's finalized head passed its latest")
	}
	base.Source(FakeBaseCdp).SetLag(0)
	// a range past the source's cap is refused; within it the logs answer
	if _, code := testRpc(t, base, FakeBaseCdp, "eth_getLogs", map[string]any{"fromBlock": "0x0", "toBlock": "0x6"}); code != -32602 {
		t.Fatalf("a range past the cap answered %d", code)
	}
	if _, code := testRpc(t, base, FakeBaseAlchemy, "eth_getLogs", map[string]any{"fromBlock": "0x0", "toBlock": "0x6"}); code != 0 {
		t.Fatalf("the other source's cap refused %d", code)
	}
	// a source that is down answers an internal error; a wrong key, 401
	base.Source(FakeBaseAlchemy).SetDown(true)
	if _, code := testRpc(t, base, FakeBaseAlchemy, "eth_blockNumber"); code != -32603 {
		t.Fatalf("a down source answered %d", code)
	}
	response, err := base.HttpClient().Post("https://"+FakeBaseAlchemyHost+"/v2/not-the-key", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a wrong key answered %d", response.StatusCode)
	}
}

func TestFakeBaseOutOfBandSender(t *testing.T) {
	base, clock := newTestBase(t, nil)
	payer := NewFakeEvmKey("computetest", "test payer")
	facilitator := NewFakeEvmKey("computetest", "test facilitator")
	outsider := NewFakeEvmKey("computetest", "test outsider")
	payee := FakeEvmAddress{0xfe, 0x02}
	base.Fund(payer.Address(), big.NewInt(1000000))
	// an authorization submitted by a sender other than the facilitator settles like any, its sender recorded
	auth, signature := testAuthorization(base, clock, payer, payee, 10000, "out of band")
	receipt, err := base.TransferWithAuthorization(outsider.Address(), auth, signature)
	if err != nil {
		t.Fatal(err)
	}
	transaction, _ := testRpc(t, base, FakeBaseCdp, "eth_getTransactionByHash", "0x"+hex.EncodeToString(receipt.TxHash[:]))
	var fields struct {
		From  string `json:"from"`
		Input string `json:"input"`
	}
	if err := json.Unmarshal(transaction, &fields); err != nil || fields.From != outsider.Address().Hex() || fields.From == facilitator.Address().Hex() ||
		!strings.HasPrefix(fields.Input, "0xe3ee160e") {
		t.Fatalf("the transaction %s", transaction)
	}
	used, _ := testRpc(t, base, FakeBaseAlchemy, "eth_getLogs", map[string]any{
		"fromBlock": "0x0", "toBlock": "latest", "address": base.Usdc().Hex(),
		"topics": []any{"0x" + hex.EncodeToString(fakeAuthorizationUsedTopic[:]), "0x" + hex.EncodeToString(fakeEvmWordAddress(payer.Address()))},
	})
	if strings.Count(string(used), `"transactionHash"`) != 1 {
		t.Fatalf("AuthorizationUsed logs %s", used)
	}
	// a transfer from the payer that settles no authorization: a Transfer, no AuthorizationUsed
	plain, err := base.Transfer(payer.Address(), FakeEvmAddress{0xfe, 0x03}, big.NewInt(500))
	if err != nil {
		t.Fatal(err)
	}
	if len(plain.Logs) != 1 || plain.Logs[0].Topics[0] != fakeTransferTopic || plain.From != payer.Address() {
		t.Fatalf("a plain transfer's receipt %+v", plain)
	}
	// the screen's reads: code, count and balances, and the token's calls, batched
	base.SetCode(payee, []byte{0x60, 0x00})
	base.SetEthBalance(payee, big.NewInt(7))
	call := func(selector [32]byte, arguments ...[]byte) map[string]any {
		data := append([]byte{}, selector[:4]...)
		for _, argument := range arguments {
			data = append(data, argument...)
		}
		return map[string]any{"to": base.Usdc().Hex(), "data": "0x" + hex.EncodeToString(data)}
	}
	batch, err := json.Marshal([]map[string]any{
		{"jsonrpc": "2.0", "id": 1, "method": "eth_getCode", "params": []any{payee.Hex(), "latest"}},
		{"jsonrpc": "2.0", "id": 2, "method": "eth_getTransactionCount", "params": []any{payer.Address().Hex(), "latest"}},
		{"jsonrpc": "2.0", "id": 3, "method": "eth_getBalance", "params": []any{payee.Hex(), "latest"}},
		{"jsonrpc": "2.0", "id": 4, "method": "eth_call", "params": []any{call(fakeBalanceOfSelector, fakeEvmWordAddress(payee)), "latest"}},
		{"jsonrpc": "2.0", "id": 5, "method": "eth_call", "params": []any{call(fakeAuthorizationStateSelector, fakeEvmWordAddress(payer.Address()), auth.Nonce[:]), "latest"}},
		{"jsonrpc": "2.0", "id": 6, "method": "eth_getTransactionCount", "params": []any{outsider.Address().Hex(), "latest"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	response, err := base.HttpClient().Post(base.Source(FakeBaseCdp).Url(), "application/json", bytes.NewReader(batch))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var answers []struct {
		Result string `json:"result"`
	}
	if err := json.NewDecoder(response.Body).Decode(&answers); err != nil || len(answers) != 6 {
		t.Fatalf("the batch answered %v", err)
	}
	want := []string{"0x6000", "0x1", "0x7", "0x" + hex.EncodeToString(fakeEvmWordUint(10000)), "0x" + hex.EncodeToString(fakeEvmWordUint(1)), "0x1"}
	for i := range want {
		if answers[i].Result != want[i] {
			t.Errorf("batch answer %d: %s, want %s", i, answers[i].Result, want[i])
		}
	}
}
