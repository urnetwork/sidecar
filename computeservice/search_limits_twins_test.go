package computeservice

// The Go twins of web search's scripts (search_limits.go, search_outcome_counts.go) for FakeRedis, which runs no Lua:
// each does what its Source does, line for line, reaching only the keys its call declared. A twin is only as true as
// its author made it, so T3 runs the Lua itself on a real Redis (Q-TEST-1).

import (
	"errors"
	"regexp"
	"strconv"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// cs_int's pattern: digits, at most 16 of them.
var twinComputeSearchCountPattern = regexp.MustCompile(`^[0-9]+$`)

// cs_int.
func twinComputeSearchCount(value string, what string) (int64, error) {
	if 16 < len(value) || !twinComputeSearchCountPattern.MatchString(value) {
		return 0, errors.New("compute search: " + what + " is no count")
	}
	return strconv.ParseInt(value, 10, 64)
}

// An array reply of bulk strings.
func twinComputeSearchBulks(values ...string) *sidecar.RedisReply {
	reply := &sidecar.RedisReply{Kind: sidecar.RedisReplyArray}
	for _, value := range values {
		reply.Replies = append(reply.Replies, &sidecar.RedisReply{Kind: sidecar.RedisReplyBulk, Bulk: []byte(value)})
	}
	return reply
}

// A hash field, false where it is absent (HMGET's false).
func twinComputeSearchField(call *sidecartest.FakeRedisScriptCall, key string, field string) (string, bool, error) {
	value, found, err := call.HashGet(key, field)
	if err != nil || !found {
		return "", false, err
	}
	return string(value), true, nil
}

// compute_search_rate.
func twinComputeSearchRate(call *sidecartest.FakeRedisScriptCall) (*sidecar.RedisReply, error) {
	key := call.Keys[0]
	now, err := twinComputeSearchCount(call.Args[0], "now")
	if err != nil {
		return nil, err
	}
	emission, err := twinComputeSearchCount(call.Args[1], "emission")
	if err != nil {
		return nil, err
	}
	tolerance, err := twinComputeSearchCount(call.Args[2], "tolerance")
	if err != nil {
		return nil, err
	}
	day := call.Args[3]
	limit, err := twinComputeSearchCount(call.Args[4], "limit")
	if err != nil {
		return nil, err
	}
	window := call.Args[5]
	ttl, err := twinComputeSearchCount(call.Args[6], "ttl")
	if err != nil {
		return nil, err
	}
	exists, err := call.Exists(key)
	if err != nil {
		return nil, err
	}
	if !exists {
		if call.Args[7] == "" {
			return twinComputeSearchBulks("absent", "0", "0", "0", "0"), nil
		}
		seed, err := twinComputeSearchCount(call.Args[7], "seed")
		if err != nil {
			return nil, err
		}
		if err := call.HashSet(key, map[string][]byte{"d": []byte(day), "c": []byte(strconv.FormatInt(seed, 10))}); err != nil {
			return nil, err
		}
	}
	tatField, tatFound, err := twinComputeSearchField(call, key, "tat")
	if err != nil {
		return nil, err
	}
	dayField, dayFound, err := twinComputeSearchField(call, key, "d")
	if err != nil {
		return nil, err
	}
	countField, countFound, err := twinComputeSearchField(call, key, "c")
	if err != nil {
		return nil, err
	}
	windowField, windowFound, err := twinComputeSearchField(call, key, "w")
	if err != nil {
		return nil, err
	}
	windowCountField, windowCountFound, err := twinComputeSearchField(call, key, "wc")
	if err != nil {
		return nil, err
	}
	count := int64(0)
	if dayFound && dayField == day && countFound {
		if count, err = twinComputeSearchCount(countField, "c"); err != nil {
			return nil, err
		}
	}
	if limit <= count {
		return twinComputeSearchBulks("day", "0", strconv.FormatInt(count, 10), "0", "0"), nil
	}
	tat := now
	if tatFound {
		stored, err := twinComputeSearchCount(tatField, "tat")
		if err != nil {
			return nil, err
		}
		tat = max(now, stored)
	}
	if tolerance < tat-now {
		return twinComputeSearchBulks("rate", strconv.FormatInt(tat-tolerance-now, 10), strconv.FormatInt(count, 10), "0", "0"), nil
	}
	windowCount := int64(0)
	first := "1"
	if windowFound && windowField == window && windowCountFound {
		if windowCount, err = twinComputeSearchCount(windowCountField, "wc"); err != nil {
			return nil, err
		}
		first = "0"
	}
	if err := call.HashSet(key, map[string][]byte{
		"tat": []byte(strconv.FormatInt(tat+emission, 10)),
		"d":   []byte(day),
		"c":   []byte(strconv.FormatInt(count+1, 10)),
		"w":   []byte(window),
		"wc":  []byte(strconv.FormatInt(windowCount+1, 10)),
	}); err != nil {
		return nil, err
	}
	if _, err := call.Expire(key, time.Duration(ttl)*time.Millisecond); err != nil {
		return nil, err
	}
	return twinComputeSearchBulks("ok", "0", strconv.FormatInt(count+1, 10), strconv.FormatInt(windowCount, 10), first), nil
}

// compute_search_rate_refund.
func twinComputeSearchRateRefund(call *sidecartest.FakeRedisScriptCall) (*sidecar.RedisReply, error) {
	key := call.Keys[0]
	emission, err := twinComputeSearchCount(call.Args[0], "emission")
	if err != nil {
		return nil, err
	}
	exists, err := call.Exists(key)
	if err != nil {
		return nil, err
	}
	if !exists {
		return &sidecar.RedisReply{Kind: sidecar.RedisReplyInteger, Integer: 0}, nil
	}
	set := map[string][]byte{}
	if tatField, found, err := twinComputeSearchField(call, key, "tat"); err != nil {
		return nil, err
	} else if found {
		tat, err := twinComputeSearchCount(tatField, "tat")
		if err != nil {
			return nil, err
		}
		set["tat"] = []byte(strconv.FormatInt(max(0, tat-emission), 10))
	}
	dayField, dayFound, err := twinComputeSearchField(call, key, "d")
	if err != nil {
		return nil, err
	}
	if countField, found, err := twinComputeSearchField(call, key, "c"); err != nil {
		return nil, err
	} else if dayFound && dayField == call.Args[1] && found {
		count, err := twinComputeSearchCount(countField, "c")
		if err != nil {
			return nil, err
		}
		set["c"] = []byte(strconv.FormatInt(max(0, count-1), 10))
	}
	windowField, windowFound, err := twinComputeSearchField(call, key, "w")
	if err != nil {
		return nil, err
	}
	if windowCountField, found, err := twinComputeSearchField(call, key, "wc"); err != nil {
		return nil, err
	} else if windowFound && windowField == call.Args[2] && found {
		windowCount, err := twinComputeSearchCount(windowCountField, "wc")
		if err != nil {
			return nil, err
		}
		set["wc"] = []byte(strconv.FormatInt(max(0, windowCount-1), 10))
	}
	if 0 < len(set) {
		if err := call.HashSet(key, set); err != nil {
			return nil, err
		}
	}
	return &sidecar.RedisReply{Kind: sidecar.RedisReplyInteger, Integer: 1}, nil
}

// compute_search_limiter.
func twinComputeSearchLimiter(call *sidecartest.FakeRedisScriptCall) (*sidecar.RedisReply, error) {
	key := call.Keys[0]
	window, err := twinComputeSearchCount(call.Args[0], "window")
	if err != nil {
		return nil, err
	}
	capacity, err := twinComputeSearchCount(call.Args[1], "capacity")
	if err != nil {
		return nil, err
	}
	own, err := twinComputeSearchCount(call.Args[2], "own")
	if err != nil {
		return nil, err
	}
	ttl, err := twinComputeSearchCount(call.Args[4], "ttl")
	if err != nil {
		return nil, err
	}
	countOf := func(field string, what string) (int64, error) {
		value, found, err := twinComputeSearchField(call, key, field)
		if err != nil {
			return 0, err
		}
		if !found {
			value = "0"
		}
		return twinComputeSearchCount(value, what)
	}
	taken, active, previous := int64(0), int64(0), int64(0)
	if storedField, found, err := twinComputeSearchField(call, key, "w"); err != nil {
		return nil, err
	} else if found {
		stored, err := twinComputeSearchCount(storedField, "w")
		if err != nil {
			return nil, err
		}
		if stored == window {
			if taken, err = countOf("n", "n"); err != nil {
				return nil, err
			}
			if active, err = countOf("a", "a"); err != nil {
				return nil, err
			}
			if previous, err = countOf("pa", "pa"); err != nil {
				return nil, err
			}
		} else if stored+1 == window {
			if previous, err = countOf("a", "a"); err != nil {
				return nil, err
			}
		}
	}
	if call.Args[3] == "1" {
		active += 1
	}
	share := max(1, capacity/max(1, active, previous))
	outcome := "ok"
	if capacity <= taken {
		outcome = "global"
	} else if share <= own {
		outcome = "share"
	} else {
		taken += 1
	}
	if err := call.HashSet(key, map[string][]byte{
		"w":  []byte(strconv.FormatInt(window, 10)),
		"n":  []byte(strconv.FormatInt(taken, 10)),
		"a":  []byte(strconv.FormatInt(active, 10)),
		"pa": []byte(strconv.FormatInt(previous, 10)),
	}); err != nil {
		return nil, err
	}
	if _, err := call.Expire(key, time.Duration(ttl)*time.Millisecond); err != nil {
		return nil, err
	}
	return twinComputeSearchBulks(outcome), nil
}

// compute_search_outcomes.
func twinComputeSearchOutcomes(call *sidecartest.FakeRedisScriptCall) (*sidecar.RedisReply, error) {
	key := call.Keys[0]
	hour, err := twinComputeSearchCount(call.Args[0], "hour")
	if err != nil {
		return nil, err
	}
	ttl, err := twinComputeSearchCount(call.Args[1], "ttl")
	if err != nil {
		return nil, err
	}
	classes := []string{"ok", "provider_error", "timeout", "refused"}
	for i, class := range classes {
		count, err := twinComputeSearchCount(call.Args[2+i], class)
		if err != nil {
			return nil, err
		}
		if count <= 0 {
			continue
		}
		field := strconv.FormatInt(hour, 10) + ":" + class
		standing := int64(0)
		if value, found, err := twinComputeSearchField(call, key, field); err != nil {
			return nil, err
		} else if found {
			if standing, err = strconv.ParseInt(value, 10, 64); err != nil {
				return nil, err
			}
		}
		if err := call.HashSet(key, map[string][]byte{field: []byte(strconv.FormatInt(standing+count, 10))}); err != nil {
			return nil, err
		}
		if err := call.HashExpire(key, []string{field}, time.Duration(ttl)*time.Millisecond); err != nil {
			return nil, err
		}
	}
	return &sidecar.RedisReply{Kind: sidecar.RedisReplyBulk, Bulk: []byte("ok")}, nil
}
