//go:build !ios_extension && !sidecar_http

// The agent working on X (DESIGN-COMPUTE §20.8's second question, §20.10's agent_find, R-SKILL-6, D-SKILL-6;
// SKILL-M11-07): AgentsClient.Find ranks the member's unretired agents for a task by the words of their status's task
// and activity, their newest summary and their names, every text read and held to its writer as agent_list reads it.
//
//	index     where the agents repo's M10 search index answers (AgentFindArgs.Index, Sidecar.Search on a Sidecar), a
//	          hit naming an agent's status or summary adds to its score, the near matches the index makes past the
//	          scan's words; where it does not answer, within SkillSettings.FindIndexWait, the scan's words alone rank
//	trust     ranking reads all text; each match says which texts it rests on and whether every one is a trusted
//	          writer's (IC-12): a match resting on an untrusted writer's status, summary or card (a tainted run's,
//	          a tagged sidecar's) is shown by its stub and the texts that matched, for the person to confirm, so no
//	          agent's own words draw the person's message to it (§20.8, DESIGN §16.11's untrusted_withheld)
//	clear     the best match is clear when it rests on trusted text alone and its score stands at least
//	          SkillSettings.FindClearMarginPercent of the next's; a clear match may be messaged with agent_send at
//	          once, any other answer waits for the person to choose
//	model     for a model an untrusted writer's match is agent_list's stub unless untrusted: include, which taints
//	          the run first, write-ahead
//	scope     mine, the member's agents repo; team (other members' announced runs, §16.10) is SKILL-M13-02's, refused
//
// On the compute legs. Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
)

// agent_find's scopes (§20.10).
const (
	AgentFindScopeMine = "mine"
	AgentFindScopeTeam = "team"
)

// The texts a match rests on.
const (
	AgentFindMatchedName     = "name"
	AgentFindMatchedTask     = "task"
	AgentFindMatchedActivity = "activity"
	AgentFindMatchedSummary  = "summary"
	AgentFindMatchedIndex    = "index"
)

var (
	// The task holds no word agent_find ranks by.
	ErrAgentFindTask = errors.New("agents: agent_find takes a task of at least one word")
	// A scope this build does not search: team waits for the Team inbox and search (SKILL-M13-02, M13b).
	ErrAgentFindScope = errors.New("agents: agent_find searches scope mine; scope team is not built yet")
)

// What a find reads.
type AgentFindArgs struct {
	Task string
	// mine, or "" for mine.
	Scope string
	// As AgentListArgs': the answer feeds a model, and untrusted: include with its taint.
	ForModel   bool
	Include    bool
	TaintFirst func(ctx context.Context) error
	// The agents repo's search index: the paths of its hits for the task, best first. Nil, or an error, ranks by the
	// scan alone.
	Index func(ctx context.Context, repoId Id, task string) ([]string, error)
}

// One agent a task matched.
type AgentFindMatch struct {
	Name  string `json:"name"`
	Score int    `json:"score"`
	// The texts the task's words matched: name, task, activity, summary, index.
	Matched []string `json:"matched"`
	// Whether every text the match rests on is a trusted writer's; false asks the person to confirm.
	Trusted bool `json:"trusted"`
	// The agent as agent_list shows it: a model's view of an untrusted writer's match is its stub.
	Agent *AgentListEntry `json:"agent"`
}

// A find's answer.
type AgentFindResult struct {
	// The words ranked by.
	Terms   []string          `json:"terms"`
	Matches []*AgentFindMatch `json:"matches"`
	// Matches past SkillSettings.FindMatchMaxCount, or past the stub cap, counted and not listed.
	More int `json:"more,omitempty"`
	// The one clear match a message may go to at once: its name, "" where none is clear.
	Clear string `json:"clear,omitempty"`
	// The person chooses before a message goes to any match: none is clear.
	Confirm bool `json:"confirm"`
	// The answer holds an untrusted writer's text: the caller's run was tainted first.
	Untrusted bool `json:"untrusted"`
	// Whether the search index answered.
	Indexed bool `json:"indexed"`
}

// The words of text agent_find ranks by: lowercase runs of letters and digits, each at least FindTermMinCharCount
// long, once each, the first FindTermMaxCount.
func agentFindTerms(text string, settings *SkillSettings) []string {
	terms := []string{}
	for _, word := range agentFindWords(text) {
		if len([]rune(word)) < settings.FindTermMinCharCount || slices.Contains(terms, word) {
			continue
		}
		terms = append(terms, word)
		if settings.FindTermMaxCount <= len(terms) {
			break
		}
	}
	return terms
}

// The lowercase runs of letters and digits in text.
func agentFindWords(text string) []string {
	return strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

// Whether term matches one of words: the same word, or, both at least FindPrefixMinCharCount long, one a prefix of the
// other, so plurals and tenses match.
func agentFindMatches(term string, words []string, settings *SkillSettings) bool {
	for _, word := range words {
		if word == term {
			return true
		}
		if settings.FindPrefixMinCharCount <= len([]rune(term)) && settings.FindPrefixMinCharCount <= len([]rune(word)) &&
			(strings.HasPrefix(word, term) || strings.HasPrefix(term, word)) {
			return true
		}
	}
	return false
}

// The agent a status or summary path of the agents repo names, "" for any other path.
func agentFindIndexName(path string, settings *SkillSettings) (AgentName, string) {
	for _, field := range []struct {
		prefix string
		suffix string
		field  string
	}{
		{prefix: "status/", suffix: agentCardFileSuffix, field: AgentFindMatchedTask},
		{prefix: agentSummaryDirectory + "/", suffix: agentSummaryFileSuffix, field: AgentFindMatchedSummary},
	} {
		rest, found := strings.CutPrefix(path, field.prefix)
		if !found {
			continue
		}
		text, found := strings.CutSuffix(rest, field.suffix)
		if !found {
			continue
		}
		name, err := ParseAgentName(text, settings)
		if err != nil {
			return "", ""
		}
		return name, field.field
	}
	return "", ""
}

// One agent's ranking: its score, the texts it rests on and whether each is trusted.
type agentFindScore struct {
	read    *AgentRead
	score   int
	matched []string
	trusted bool
}

// Adds weight for a text that matched, and its trust.
func (self *agentFindScore) add(field string, weight int, trusted bool) {
	self.score += weight
	if !slices.Contains(self.matched, field) {
		self.matched = append(self.matched, field)
	}
	self.trusted = self.trusted && trusted
}

// Ranks the member's agents for args.Task (see the file header).
func (self *AgentsClient) Find(ctx context.Context, args *AgentFindArgs) (*AgentFindResult, error) {
	if args == nil {
		return nil, ErrAgentFindTask
	}
	switch args.Scope {
	case "", AgentFindScopeMine:
	case AgentFindScopeTeam:
		return nil, ErrAgentFindScope
	default:
		return nil, fmt.Errorf("%w: scope %q", ErrAgentFindScope, args.Scope)
	}
	if args.ForModel && args.Include && args.TaintFirst == nil {
		return nil, ErrAgentsTaintFirst
	}
	terms := agentFindTerms(args.Task, self.settings)
	if len(terms) == 0 {
		return nil, ErrAgentFindTask
	}
	place, err := self.placeWithRepo()
	if err != nil {
		return nil, err
	}
	// the ranking reads every text, whoever wrote it; what returns to a model is held below
	read, err := self.ReadAgents(ctx, &AgentsReadArgs{})
	if err != nil {
		return nil, err
	}
	result := &AgentFindResult{Terms: terms, Matches: []*AgentFindMatch{}}
	scores := map[AgentName]*agentFindScore{}
	scoreOf := func(agent *AgentRead) *agentFindScore {
		score := scores[agent.Card.Name]
		if score == nil {
			score = &agentFindScore{read: agent, trusted: true}
			scores[agent.Card.Name] = score
		}
		return score
	}
	readsByName := map[AgentName]*AgentRead{}
	for _, agent := range read.Agents {
		card := agent.Card.Card
		if card == nil || card.Person() {
			// the person's me is no agent at work
			continue
		}
		readsByName[card.Name] = agent
		cardTrusted := agentsTextTrusted(place.authority, place.memberId, agent.Card.WriterSidecarId, agent.Card.Provenance)
		nameWords := agentFindWords(strings.ReplaceAll(string(card.Name), "-", " "))
		var taskWords, activityWords, summaryWords []string
		statusTrusted, summaryTrusted := false, false
		if status := agent.Status; status != nil && status.Status != nil {
			taskWords, activityWords = agentFindWords(status.Status.Task), agentFindWords(status.Status.Activity)
			statusTrusted = status.Trusted
		}
		if summary := agent.Summary; summary != nil && summary.Summary != nil {
			summaryWords = agentFindWords(summary.Summary.Text)
			summaryTrusted = summary.Trusted
		}
		for _, term := range terms {
			for _, field := range []struct {
				name    string
				words   []string
				weight  int
				trusted bool
			}{
				{name: AgentFindMatchedName, words: nameWords, weight: self.settings.FindNameWeight, trusted: cardTrusted},
				{name: AgentFindMatchedTask, words: taskWords, weight: self.settings.FindTaskWeight, trusted: statusTrusted},
				{name: AgentFindMatchedActivity, words: activityWords, weight: self.settings.FindActivityWeight, trusted: statusTrusted},
				{name: AgentFindMatchedSummary, words: summaryWords, weight: self.settings.FindSummaryWeight, trusted: summaryTrusted},
			} {
				if agentFindMatches(term, field.words, self.settings) {
					scoreOf(agent).add(field.name, field.weight, field.trusted)
				}
			}
		}
	}
	if args.Index != nil {
		paths, err := args.Index(ctx, place.agentsRepoId, args.Task)
		if err == nil {
			result.Indexed = true
			counted := map[AgentName]bool{}
			for _, path := range paths {
				name, field := agentFindIndexName(path, self.settings)
				agent := readsByName[name]
				if agent == nil || counted[name] {
					continue
				}
				counted[name] = true
				// a hit counts on the trust of the text it names as its writer's read took it
				trusted := false
				switch field {
				case AgentFindMatchedTask:
					trusted = agent.Status != nil && agent.Status.Status != nil && agent.Status.Trusted
				case AgentFindMatchedSummary:
					trusted = agent.Summary != nil && agent.Summary.Summary != nil && agent.Summary.Trusted
				}
				scoreOf(agent).add(AgentFindMatchedIndex, self.settings.FindIndexWeight, trusted)
			}
		}
	}
	ranked := []*agentFindScore{}
	for _, score := range scores {
		if 0 < score.score {
			ranked = append(ranked, score)
		}
	}
	slices.SortFunc(ranked, func(a *agentFindScore, b *agentFindScore) int {
		if a.score != b.score {
			return b.score - a.score
		}
		return strings.Compare(string(a.read.Card.Name), string(b.read.Card.Name))
	})
	if self.settings.FindMatchMaxCount < len(ranked) {
		result.More = len(ranked) - self.settings.FindMatchMaxCount
		ranked = ranked[:self.settings.FindMatchMaxCount]
	}
	if 0 < len(ranked) && ranked[0].trusted &&
		(len(ranked) == 1 || ranked[1].score*self.settings.FindClearMarginPercent <= ranked[0].score*100) {
		result.Clear = string(ranked[0].read.Card.Name)
	}
	result.Confirm = result.Clear == ""
	if args.ForModel && args.Include {
		untrusted := slices.ContainsFunc(ranked, func(score *agentFindScore) bool { return !score.read.Trusted })
		if untrusted {
			// the taint goes first, write-ahead: a failure returns nothing
			if err := args.TaintFirst(ctx); err != nil {
				return nil, fmt.Errorf("%w: %w", ErrAgentsTaintFirst, err)
			}
			result.Untrusted = true
		}
	}
	now := self.clock.Now()
	stubBytes := 0
	for i, score := range ranked {
		match := &AgentFindMatch{Name: string(score.read.Card.Name), Score: score.score, Matched: score.matched, Trusted: score.trusted}
		if args.ForModel && !args.Include && !score.read.Trusted {
			stub := agentListStubOf(self.stub(score.read, self.writerLabel(agentsUntrustedWriter(score.read))))
			if self.settings.StubByteCount < stubBytes+len(stub.Text) {
				result.More += len(ranked) - i
				break
			}
			stubBytes += len(stub.Text)
			match.Agent = &AgentListEntry{Name: match.Name, Stub: stub}
		} else {
			match.Agent = agentListEntryOf(score.read, now)
		}
		result.Matches = append(result.Matches, match)
	}
	return result, nil
}

// The writer a stub of read is labeled with: its first untrusted text's.
func agentsUntrustedWriter(read *AgentRead) Id {
	writer := read.Card.WriterSidecarId
	if read.Status != nil && read.Status.Status != nil && !read.Status.Trusted {
		writer = read.Status.WriterSidecarId
	} else if read.Summary != nil && read.Summary.Summary != nil && !read.Summary.Trusted {
		writer = read.Summary.WriterSidecarId
	}
	return writer
}

// The find as a model reads it: the clear match where there is one, else the matches for the person to choose from,
// each with the texts it rests on and whether they are trusted; an untrusted writer's match as its stub.
func (self *AgentFindResult) ModelText(fence func(sender string, text string) string) string {
	if len(self.Matches) == 0 {
		return "No agent's status, summary or name matches: " + strings.Join(self.Terms, " ") + "."
	}
	builder := strings.Builder{}
	switch {
	case self.Clear != "":
		builder.WriteString("One clear match, on trusted text: " + self.Clear + ". You may message it with agent_send.\n")
	default:
		builder.WriteString("No clear match: show these to your person and ask which agent they mean before you message one.\n")
	}
	for _, match := range self.Matches {
		trust := "trusted text"
		if !match.Trusted {
			trust = "untrusted text: confirm with your person"
		}
		builder.WriteString(fmt.Sprintf("\n%s, score %d, matched %s (%s)\n", match.Name, match.Score, strings.Join(match.Matched, ", "), trust))
		switch {
		case match.Agent == nil:
		case match.Agent.Stub != nil:
			builder.WriteString(match.Agent.Stub.Text + "\n")
		default:
			block := agentListEntryText(match.Agent)
			if !match.Agent.Trusted && fence != nil {
				block = fence("agent "+match.Name, block)
			}
			builder.WriteString(block + "\n")
		}
	}
	if 0 < self.More {
		builder.WriteString(fmt.Sprintf("\n%d more matches are not listed.\n", self.More))
	}
	return strings.TrimRight(builder.String(), "\n")
}
