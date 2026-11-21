//go:build !sidecar_http && !ios_extension

// A bridge for QD-1148's external tests (directory_cards_erasure_note_test.go): the card writer's journal as every card
// write reads it, so a test sees what a sync journaled before any card is written.

package sidecar

// One item the card writer's journal leaves out.
type DirectoryCardJournaledForTest struct {
	AnnouncementId Id
	// The erasure whose moderation's note named it, journaled at a sync; nil for one a return's read of the erasure
	// set found.
	NotedBy *Id
}

// The journal, oldest first.
func (self *DirectoryClient) CardJournalForTest() ([]*DirectoryCardJournaledForTest, error) {
	written, err := self.readCardWritten()
	if err != nil {
		return nil, err
	}
	journaled := []*DirectoryCardJournaledForTest{}
	for _, moderated := range written.Moderated {
		journaled = append(journaled, &DirectoryCardJournaledForTest{AnnouncementId: moderated.AnnouncementId, NotedBy: moderated.NotedBy})
	}
	return journaled, nil
}
