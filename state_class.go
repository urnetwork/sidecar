// §5.9's file classes that are named on every leg, whichever leg links the code that writes them. A class's files are
// sealed under the class's own key (state_seal.go), and a component may not take a class's name for its own
// (sidecar_component.go's reserved names), so a name is held here even where its store is tagged off: the ios_extension
// legs link no index cache (QD-988), and no component there may be called search.

package sidecar

// §5.9's file class of the index cache and search state (state_search_cache.go, state_search_state.go), which the
// search journal shares (evs_index_journal.go).
const SidecarSearchFileClass = "search"
