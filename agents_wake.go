//go:build !ios_extension && !sidecar_http

// Wakes (DESIGN-COMPUTE §20.7's loops and wakes row, D-SKILL-11, CF-10; SKILL-M11-05): an agent wakes for inbox
// messages at most SkillSettings.MaxWakesPerHour times a WakeWindow without a person's input, at most
// MaxWakesPerSender of them for one sending sidecar, and a thread holds at most ThreadMessageMax messages; past either
// the delivery stops queuing and the agent's status says so, the message waiting in the inbox for the next turn its
// person drives.
//
//	sender    counted by the verified sending sidecar, the push's signer, never by from; a support notice counts as one
//	          sender, support (Q-SUP-11)
//	person    a person's input (a prompt, a steer, a follow-up, an Answer in the app) starts the agent's counts again
//	window    sliding: a wake older than WakeWindow no longer counts
//
// On the compute legs. Safe for concurrent use.

package sidecar

import (
	"sync"
	"time"
)

// The sender a support notice counts as (Q-SUP-11).
const AgentWakeSenderSupport = "support"

// Why a wake was refused.
type AgentWakeRefusal string

const (
	// MaxWakesPerHour wakes in the window.
	AgentWakeRefusalHour AgentWakeRefusal = "wakes_per_hour"
	// MaxWakesPerSender wakes in the window for this sender.
	AgentWakeRefusalSender AgentWakeRefusal = "wakes_per_sender"
	// ThreadMessageMax messages in the thread.
	AgentWakeRefusalThread AgentWakeRefusal = "thread_full"
)

// One agent's wakes in the window, oldest first, and each sender's.
type agentWakeCounts struct {
	wakes        []time.Time
	senderWakes  map[string][]time.Time
	refusedSince time.Time
}

// One host's wake limits for its agents: see the file header.
type AgentWakeLimiter struct {
	settings *SkillSettings

	stateLock sync.Mutex
	agents    map[AgentName]*agentWakeCounts
}

// A limiter on settings' bounds.
func NewAgentWakeLimiter(settings *SkillSettings) *AgentWakeLimiter {
	if settings == nil {
		settings = DefaultSkillSettings()
	}
	return &AgentWakeLimiter{settings: settings, agents: map[AgentName]*agentWakeCounts{}}
}

// The times still in the window at now.
func agentWakeWindowed(times []time.Time, now time.Time, window time.Duration) []time.Time {
	kept := times[:0]
	for _, at := range times {
		if now.Sub(at) < window {
			kept = append(kept, at)
		}
	}
	return kept
}

// Whether agent may wake now for a message from sender, in a thread already holding threadMessageCount messages; an
// allowed wake is counted. A refusal names its limit.
func (self *AgentWakeLimiter) Allow(agent AgentName, sender string, threadMessageCount int, now time.Time) (bool, AgentWakeRefusal) {
	if self.settings.ThreadMessageMax < threadMessageCount {
		return false, AgentWakeRefusalThread
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	counts := self.agents[agent]
	if counts == nil {
		counts = &agentWakeCounts{senderWakes: map[string][]time.Time{}}
		self.agents[agent] = counts
	}
	counts.wakes = agentWakeWindowed(counts.wakes, now, self.settings.WakeWindow)
	senderWakes := agentWakeWindowed(counts.senderWakes[sender], now, self.settings.WakeWindow)
	counts.senderWakes[sender] = senderWakes
	switch {
	case self.settings.MaxWakesPerHour <= len(counts.wakes):
		counts.refusedSince = now
		return false, AgentWakeRefusalHour
	case self.settings.MaxWakesPerSender <= len(senderWakes):
		counts.refusedSince = now
		return false, AgentWakeRefusalSender
	}
	counts.wakes = append(counts.wakes, now)
	counts.senderWakes[sender] = append(senderWakes, now)
	return true, ""
}

// A person's input to agent: its counts start again.
func (self *AgentWakeLimiter) PersonInput(agent AgentName) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.agents, agent)
}

// The wakes agent took in the window at now.
func (self *AgentWakeLimiter) Count(agent AgentName, now time.Time) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	counts := self.agents[agent]
	if counts == nil {
		return 0
	}
	counts.wakes = agentWakeWindowed(counts.wakes, now, self.settings.WakeWindow)
	return len(counts.wakes)
}

// The key a message's sender counts under: its push's signer, or support for a support notice.
func agentWakeSender(message *AgentMessageRead) string {
	if message.Trust != nil && message.Trust.Class == AgentMessageTrustSupport {
		return AgentWakeSenderSupport
	}
	return message.SignerSidecarId.String()
}
