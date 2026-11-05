# Prior art: search over end-to-end-encrypted data (production E2EE products vs. SSE)

_Researched 2026-11-05. Code citations point at each project's public GitHub default branch as of that date (`/blob/HEAD/...`). "Cited Findings" holds only sourced facts; my own conclusions are under "Inferences"; "(search excerpt)" marks claims taken from search-engine summaries rather than a page I fetched myself._

## 1. Tuta (formerly Tutanota): how its encrypted search index works

### Takeaway
Tuta builds its search index entirely on the client. It works from decrypted mail and contacts and keeps the index only on the device. The index is never uploaded or synced, so every browser and device rebuilds its own.

There have been two backends:
- **IndexedDB (2017 onward, still used in the browser).** A hand-rolled inverted index: words and element IDs are deterministically encrypted, posting-list chunks are encrypted with random IVs, and each word has an encrypted metadata row.
- **SQLite FTS5 (since March 2025, desktop and mobile).** A contentless FTS5 index inside the SQLCipher-encrypted offline database.

I found no published size or performance figures and no academic paper.

### Cited Findings
**Public statements**
- **Announcement (2017-12-21).** Steps: "The data is indexed", then "The search index is encrypted and stored locally on the client". The scope is "encrypted emails and encrypted contacts". The server has "zero access" to the data and the search metadata, and the search code is GPLv3. The post gives no data structures, no numbers and no academic collaboration. — [Tuta blog, 2017](https://tuta.com/blog/first-search-encrypted-data)
- **Security page.** The encrypted index is stored locally on the device or in the browser, because Tuta cannot search data that is encrypted on the server. — [Tuta security page](https://tuta.com/security) (search excerpt)
- **Security review.** A review issue on GitHub reports that all search words and suggestions in the index are encrypted. It also reports that the IndexedDB database name is not linked to the user's mail address. — [tutao/tutanota#2787](https://github.com/tutao/tutanota/issues/2787) (search excerpt)
- **Older user complaint.** An issue asks for a persistent offline search database, because "every time i try to search, i have to reindex entire mailbox, takes ages". — [tutao/tutanota#2681](https://github.com/tutao/tutanota/issues/2681) (search excerpt)
- **Whole-mailbox index (2026-08-23).** The post says: "Before we rolled out this new search improvement, we would only had partial search index… We've now changed this to index your whole mailbox". It adds that "all old emails are downloaded and stored end-to-end encrypted locally on your device". It names no technology, platforms or timings. Its only "10x" figure is about FastSync, which is not search. — [Tuta blog, 2026](https://tuta.com/blog/tuta-mail-search-is-now-faster)

**Backend split (code)**
- **Commit of 2025-03-13**, "Add SQLite search on clients where offline storage is available". It reads "Introduce a separate Indexer for SQLite using FTS5" and "Split search backends and use the right one based on client (IndexedDB for Browser, and OfflineStorage everywhere else)". — [commit 86d5775](https://github.com/tutao/tutanota/commit/86d5775e16ed441695457f2567ffeec9478bf109)

**IndexedDB backend: data structures** — [SearchTypes.ts](https://github.com/tutao/tutanota/blob/HEAD/src/applications/common/api/worker/search/SearchTypes.ts)
- **`EncryptedSearchIndexEntry`.** "First part encrypted element id (16 bytes), second part encoded and encrypted attribute and positions."
- **`SearchIndexDbRow`.** "Binary encoded EncryptedSearchIndexEntries", i.e. one chunk of a posting list.
- **`SearchIndexMetaDataDbRow {id, word, rows}`.** `rows` holds "sequences of numbers like: [app, type, indexRowId, size, …] encoded and encrypted".
  - Decoded, each entry is a `SearchIndexMetadataEntry {key, size, app, type, oldestElementTimestamp}`.
  - App and type sit in the metadata "to filter for type (mail, contact, users) before loading and decrypting index rows".
- **`ElementDataDbRow [listId, enc meta row keys, ownerGroup]`.** This is a reverse map from each item to the metadata rows that hold its postings. The listId lives here "instead of SearchIndexEntry to allow moving mails without changing the SearchIndexEntries".
- **`GroupData {lastBatchIds, indexTimestamp, groupType}`.** Tracks indexing progress for each mail group.
- **`IndexUpdate`.** Carries `create`, `move` and `delete` sets for each type.
- **Object stores and row size.** The stores are SearchIndexOS, SearchIndexMetaDataOS, ElementDataOS, MetaDataOS and GroupDataOS. A posting row holds at most `SEARCH_INDEX_ROW_LENGTH = 1000` entries and is split when it would exceed that. During initial indexing (which moves back in time), the code prefers to put entries into the second row. — [IndexerCore.ts](https://github.com/tutao/tutanota/blob/HEAD/src/applications/mail-app/workerUtils/index/IndexerCore.ts)

**IndexedDB backend: encryption** — [IndexEncryptionUtils.ts](https://github.com/tutao/tutanota/blob/HEAD/src/applications/common/api/worker/search/IndexEncryptionUtils.ts), [IndexedDbIndexer.ts](https://github.com/tutao/tutanota/blob/HEAD/src/applications/mail-app/workerUtils/index/IndexedDbIndexer.ts)
- **Words.** Index keys are encrypted with AES-256 using a fixed database IV (`dbInitializationVector`), and the IV is then sliced off. The ciphertext is therefore deterministic. Metadata is looked up by encrypted word through the `SearchIndexWordsIndex`.
- **Element IDs.** IDs are decrypted with the same database IV, so they are deterministic too.
- **Entry payloads and metadata rows.** These use `aes256EncryptSearchIndexEntry` and are read back with `aesDecryptUnauthenticated`, so there is no integrity check.
- **Database key.** At creation the code generates a random AES-256 key and IV (`aes256RandomKey`, `generateInitializationVector`). The key is encrypted with the user group key (`userEncDbKey`). It is stored in the local MetaDataOS together with the encrypted IV and `userGroupKeyVersion`.

**IndexedDB backend: indexing scope**
- **Free accounts.** `FREE_MAIL_INDEX_DEFAULT_RANGE_DAYS = 28`. — [TutanotaConstants.ts](https://github.com/tutao/tutanota/blob/HEAD/src/platform-kit/app-env/TutanotaConstants.ts)
- **Batching.** The web indexer works back in time in one-day batches (`MAIL_INDEX_BATCH_INTERVAL = TimeConstants.DAY_IN_MILLIS`). — [WebMailIndexer.ts](https://github.com/tutao/tutanota/blob/HEAD/src/applications/mail-app/workerUtils/index/WebMailIndexer.ts)

**SQLite/FTS5 backend (native clients)** — [OfflineStoragePersistence.ts](https://github.com/tutao/tutanota/blob/HEAD/src/applications/mail-app/workerUtils/index/OfflineStoragePersistence.ts)
- **`mail_index`** is `fts5(subject, toRecipients, ccRecipients, bccRecipients, sender, body, attachments, content='', contentless_delete=1, tokenize='signal_tokenizer')`.
- **`content_mail_index(receivedDate, sets)`** is a separate table. The code says "we would love to use the contentless_unindexed option, but it's only available from SQLite 3.47.0 onwards".
- **`contact_index`** is `fts5(firstName, lastName, mailAddresses)` and is not contentless. The reason given is so that results can be sorted by name inside the query with LIMIT, at the cost of duplicating some data.
- **Supporting tables.**
  - `search_group_data` tracks progress.
  - `encrypted_mail_details_blobs` is temporary storage "to avoid storing all of the user's archives in RAM".
  - `cached_mail_details_archives` exists "to prevent redownloading entire archives".
  - All of these are `purgedWithCache: true`.
- **Database.** The database is accessed through `SqlCipherFacade`.
- **Queries.** FTS5 MATCH with prefix tokens (`"free"*` matches "freedom"), column filters, date and folder ("sets") filters, and `ORDER BY content_mail_index.receivedDate DESC`. — [OfflineStorageSearchFacade.ts](https://github.com/tutao/tutanota/blob/HEAD/src/applications/mail-app/workerUtils/index/OfflineStorageSearchFacade.ts)
- **Chunking and target.** `INDEX_CHUNK_SIZE = 1000`. Native clients aim for `FULL_INDEXED_TIMESTAMP`, i.e. the whole mailbox. — [OfflineMailIndexer.ts](https://github.com/tutao/tutanota/blob/HEAD/src/applications/mail-app/workerUtils/index/OfflineMailIndexer.ts)
- **Tokenizer.** `signal_tokenizer` is Signal's FTS5 extension. It segments text using Unicode word rules, removes diacritics and lowercases, which "enables application to support CJK symbols in full-text search". — [signalapp/Signal-FTS5-Extension](https://github.com/signalapp/Signal-FTS5-Extension)

### Inferences
- **Multi-device.** Each device builds its own index.
  - The database key is random for each device and kept locally, and every search table is purged with the local cache. Nothing can be synced from or recovered via the server.
  - A new browser or device must download and decrypt the mail again and reindex it. On native clients this now means the whole mailbox (the 2026 post).
- **Update on new mail.** Updates are incremental and driven by entity events (`IndexUpdate` create/move/delete). Moves only rewrite the ElementData listId.
- **Local leakage.**
  - In IndexedDB, deterministic word ciphertexts reveal word equality and posting-list sizes (row counts and `size` fields) to anyone holding the profile files.
  - Under SQLCipher the FTS5 index is plaintext inside an encrypted database file.
  - Neither design was meant to be stored server-side. Uploaded per row, Tuta's IndexedDB layout would hand the server classic SSE-style frequency leakage (see §5).
- **Reusable format idea.** The IndexedDB layout is a worked encrypted inverted index:
  - a deterministic term key, pointing to
  - an encrypted metadata row with (type, row id, size, oldest timestamp), pointing to
  - posting chunks of at most 1000 entries,
  - plus a reverse map from item to its rows, used for deletion.

  Inside a single encrypted blob, the deterministic parts would not matter.

### Gaps
- No academic paper or university collaboration on Tuta search turned up, and the 2017 post mentions none.
- No published index sizes, build times or query latencies.
- I did not verify the AES mode or IV handling inside `aes256EncryptSearchIndexEntry`.
- Whether Tuta sets the FTS5 `secure-delete` option is unknown. A GitHub code search for `"secure-delete"` in tutao/tutanota returned no hits; see §7.

## 2. Proton Mail encrypted (message content) search

### Takeaway
Proton's content search is opt-in, and the support documentation covers the web app only. Each browser on each device downloads and decrypts the user's messages and builds its own local index in IndexedDB.

The index is a forward index: message ID maps to the cleaned body plus metadata. Each entry is AES-GCM encrypted under a key stored on the device. Neither the index nor any query ever reaches Proton.

Message bodies are indexed. The library's sizing heuristic is a cache of about 500 MB, enough for about 50k emails. I found no official confirmation of content search on mobile.

### Cited Findings
**Engineering post (Marco Martinoli, Proton Cryptography team; the page shows 2022-08-31)** — [Proton engineering blog](https://proton.me/blog/engineering-message-content-search)
- **Index shape.** The index is "built locally" in IndexedDB. It is a forward index, keyed by message ID, whose values are cleaned message content. An inverted index was explored but not adopted.
- **Pipeline.** Each message is decrypted from OpenPGP and stripped of HTML. It is then re-encrypted with AES-GCM via WebCrypto, chosen because it is faster than OpenPGP in browsers.
- **Key.** The key is generated at the start of indexing and stored locally, reportedly "encrypted under the user's contact key".
- **Caching.** The index is cached unencrypted "fully or partially, depending on its size".
- **Search and results.** A search first filters on metadata (for example a date range), then matches keywords against the body and metadata. Opening a result re-fetches the message, because the local copy lacks the HTML.
- **Privacy and logout.** Neither the index nor the query is ever sent to the server, and logging out does not delete the index.
- **Future work.** The post raises an inverted index or "searchable encryption if performance requires it", and possible reuse in Drive and Calendar.
- A search tool listed this page as about 257 days old, but the fetched page is dated 2022-08-31, so it may have been re-dated or updated.

**Support documentation** — [Proton support: search message content](https://proton.me/support/search-message-content)
- **Per-device index.** "You must create an index of your messages for each browser on each device." The index "never leaves" the browser.
- **Encryption at rest.** Each message in the index is encrypted. It can be decrypted only "when you're logged in on the device hosting the index", and a decrypted copy is held in memory while you are logged in.
- **Size.** The index is limited by the browser's storage capacity. For very large inboxes, a date shows how far back content search reaches, and that date moves forward as new mail arrives.
- **Build.** Indexing "may take a few minutes and can be quite resource-intensive" and can be paused and resumed. After the browser has been idle, the index "might need a few seconds to update".
- **Removing the index.** Signing out keeps the index. Clearing browser data erases it. Turning the switch off does not erase it. Private mode may not work.

**Library internals (code)**
- **Constants.** — [constants.ts](https://github.com/ProtonMail/WebClients/blob/HEAD/packages/encrypted-search/lib/constants.ts)
  - `ES_MAX_CACHE = 600_000_000` (600 MB). The comment reads: "it should be enough for ~50k emails, and more than 95% of paid users have less than that, based on an extrapolation made in 2021… The target size is 500 MB".
  - `ES_MAX_PARALLEL_ITEMS = 150`, which is one metadata page from the mail API.
  - `ES_MAX_CONCURRENT = 20` concurrent fetches, or 1 in background mode.
  - `ES_MAX_ITEMS_PER_BATCH = 1_000` reads from IndexedDB.
  - `INDEXEDDB_VERSION = 4`.
  - Content fetches retry up to 10 times, with at most 24 h between retries and a 2-day timeout on the retry queue.
- **IndexedDB stores.** `configObjectStore`, `content`, `events`, `indexingProgress`, `metadata` and `metadataOldest`. — [esIDB directory](https://github.com/ProtonMail/WebClients/tree/HEAD/packages/encrypted-search/lib/esIDB)
  - `content` is keyed by item ID and holds an `aesGcmCiphertext` under an `IndexKey`. — [content.ts](https://github.com/ProtonMail/WebClients/blob/HEAD/packages/encrypted-search/lib/esIDB/content.ts)
  - `metadata` values carry a `timepoint` next to the `aesGcmCiphertext`. — [metadata.ts](https://github.com/ProtonMail/WebClients/blob/HEAD/packages/encrypted-search/lib/esIDB/metadata.ts)
- **Original repository.** The standalone `ProtonMail/encrypted-search` repository is archived and read-only. — [GitHub](https://github.com/ProtonMail/encrypted-search) (search excerpt)

**Mobile**
- A 2025 secondary source says mobile users cannot search message content, only subject, to and from. — [NBTV Substack](https://nbtv.substack.com/p/turn-this-on-now) (secondary)
- I found no official announcement of mobile content search.

### Inferences
- **What the index really is.** It is an encrypted local copy of the plaintext corpus, searched by linear scan over a decrypted cache. 500 MB for about 50k emails works out to roughly 10 KB of cleaned text per email. Proton itself flags that it scales poorly.
- **Incremental updates.** The `events` store suggests that Proton's event stream drives incremental updates and deletes. That comes from the store name; I found no documentation of it.
- **Local timestamps in the clear.** `timepoint` sits unencrypted next to the ciphertext in the local database. Message timestamps are therefore visible to someone with disk access, though not to the server.
- **Multi-device.** There is no sync at all; every device and browser pays the full download, decrypt and index cost.

### Gaps
- No official figures for build time, query latency or size on disk.
- Status on desktop, iOS and Android as of late 2026 is unconfirmed by Proton.
- The fetched sources do not document how event-loop updates or deletions are handled.

## 3. Other E2EE products (local-only indexes): Keybase, Signal/WhatsApp, Skiff, Element/Matrix, Standard Notes/Notesnook/CryptPad, Apple

### Takeaway
Every mail and chat product here builds the index on the device and keeps it in an encrypted local store. That store is LevelDB with encryption, SQLCipher, or an encrypted IndexedDB blob. None of them syncs a text index through the server, so each device reindexes. Skiff is the closest structural match to "one encrypted whole-index blob", though it kept the blob only locally.

### Cited Findings
**Keybase chat** (Keybase was acquired by Zoom in 2020 — [Wikipedia](https://en.wikipedia.org/wiki/Keybase))
- **Storage.** The search indexer uses "encrypted on-disk storage" through the `encrypteddb` package. — [chat/search/indexer.go](https://github.com/keybase/client/blob/HEAD/go/chat/search/indexer.go), [chat/search/storage.go](https://github.com/keybase/client/blob/HEAD/go/chat/search/storage.go)
- **Entries.** Token and alias entries are versioned (`indexVersion = 16`). The comments warn that hot tokens have large posting lists, so flushing every batch causes "wasteful re-encryption of hot tokens". — [chat/search/storage.go](https://github.com/keybase/client/blob/HEAD/go/chat/search/storage.go)
- **Realtime updates.** "If a conversation doesn't meet the minimum requirements, don't update the index realtime. The priority score emphasizes how much of the conversation is read." — [chat/search/indexer.go](https://github.com/keybase/client/blob/HEAD/go/chat/search/indexer.go)
- **Tokenizer and limits.** — [chat/search/constants.go](https://github.com/keybase/client/blob/HEAD/go/chat/search/constants.go)
  - `MinTokenLength = 3` and `maxPrefixLength = 10`, so prefixes are indexed.
  - Background "SelectiveSync" covers at most 100 conversations on desktop and 10 on mobile. It starts after 10 s or 20 s and runs every 5 min or 15 min respectively.
  - `MaxAllowedSearchHits = 10000`. A regexp fallback is capped at 100,000 messages.

**KBFS (Keybase file system) search**
- **Index.** A Bleve index over a LevelDB key-value store, written into a KBFS filesystem. The code says: "Store the index in a KBFS private folder for the current user… Everything will be encrypted as if it were in the user's own private KBFS folder." — [kbfs/search/indexer.go](https://github.com/keybase/client/blob/HEAD/go/kbfs/search/indexer.go)
- **Local-only servers.** The index's KBFS config points its block server and metadata server at local `dir:` paths: `<storageRoot>/kbfs_index/<version>/<uid>/{bserver,mdserver}`. The journal is off and the disk cache is off. The comment reads "Make a per-user index for all the TLFs indexed locally by that user". — [kbfs/search/init.go](https://github.com/keybase/client/blob/HEAD/go/kbfs/search/init.go)
- **What gets indexed.** Indexing is driven by the `SyncedTlfObserver` callbacks (`FullSyncStarted`, `SyncModeChanged`). This implies, but I did not fully verify, that only top-level folders (KBFS's shared roots, "TLFs") the user has set to sync to the device are indexed. — [kbfs/search/indexer.go](https://github.com/keybase/client/blob/HEAD/go/kbfs/search/indexer.go)

**Signal and WhatsApp**
- Signal publishes `signal_tokenizer`, a C-ABI tokenizer for SQLite FTS5 aimed at local full-text search, including CJK. — [Signal-FTS5-Extension](https://github.com/signalapp/Signal-FTS5-Extension)

**Skiff** (discontinued: services sunset on 2024-08-09 after the Notion acquisition announced in February 2024 — [Reclaim The Net](https://reclaimthenet.org/private-email-and-documents-company-skiff-is-shutting-down-after-notion-acquisition), [AlternativeTo](https://alternativeto.net/news/2024/2/notion-acquires-the-privacy-focused-platform-skiff-ending-its-services-within-6-months/))
- **Index and storage.** The `skiff-front-search` library keeps a MiniSearch index in memory. — [searchIndex.ts](https://github.com/skiff-org/skiff-apps/blob/HEAD/libs/skiff-front-search/src/searchIndex.ts)
  - On save it calls `miniSearch.vacuum()`, serializes the whole index with `toJSON()` into a compressed JSON datagram (`createRawCompressedJSONDatagram`), encrypts it, and writes it to IndexedDB with `idb-keyval` under a per-user key.
  - Saves are debounced with `maxWait: 30_000`.
  - If decryption fails, the index is deleted and rebuilt.
- **Encryption.** The library uses a random symmetric key for the index. That key is encrypted with the user's keypair (`stringEncryptAsymmetric`) and stored alongside it as `{encryptedKey, encryptedSearchIndex}`. — [encryption.ts](https://github.com/skiff-org/skiff-apps/blob/HEAD/libs/skiff-front-search/src/encryption.ts)
- **Documentation.**
  - The repository README says the library "was documented in [this blog post](https://skiff.com/blog/private-search)". I could not retrieve the post (site defunct, and the archive fetch was blocked). — [skiff-apps README](https://github.com/skiff-org/skiff-apps)
  - The 2022 whitepaper mentions only "client-side search indexing algorithms". — [Skiff Whitepaper 2022](https://skiff-org.github.io/whitepaper/Skiff_Whitepaper_2022.pdf)

**Element / Matrix (Seshat)**
- **What Seshat is.** Seshat is "a database and indexer for Matrix events… a full text search backend for Matrix clients". Live events are added, then committed after each sync. — [matrix-org/seshat](https://github.com/matrix-org/seshat)
- **Storage.** Seshat stores its data encrypted on disk with SQLCipher. The event indexer downloads, stores and indexes messages from E2E encrypted rooms. — [Element Desktop native-modules doc (mirror)](https://git.piskot.si/nikrozman/element-desktop/raw/branch/develop/docs/native-node-modules.md)
- **Availability.** Search in encrypted rooms is "only possible using the desktop client" and must be enabled in Settings → Security & Privacy. — [KIT Matrix docs](https://docs.matrix.kit.edu/en/messaging/search/)

**Notesnook, Standard Notes, CryptPad**
- **Notesnook.** Its core uses SQLite FTS5: code search finds FTS5 in `packages/core/src/database/migrations.ts`, `packages/core/src/api/lookup.ts` and `packages/core/src/utils/query-transformer.ts`. — [streetwriters/notesnook](https://github.com/streetwriters/notesnook/blob/HEAD/packages/core/src/database/migrations.ts)
- **Standard Notes.** Notes, files and tags are encrypted on the device, and the sync server stores only ciphertext, so the server cannot search content. — [Helge Klein review](https://helgeklein.com/blog/standard-notes-note-taking-app-with-client-side-encryption) (third-party)
- **CryptPad.** Not researched; see Gaps.

**Apple (iCloud Advanced Data Protection, Photos)**
- **Advanced Data Protection (ADP).** — [Apple support 102651](https://support.apple.com/en-us/102651)
  - With ADP on, 25 data categories are end-to-end encrypted, including iCloud Drive, Photos, Notes, Messages in iCloud and Backup. Mail, Contacts and Calendars are not.
  - Some metadata stays under standard protection, including iCloud Drive's "raw byte checksums of the file content and the file name", photo and video checksums, modification dates, file size and file type. "This metadata is always encrypted, but the encryption keys are still stored by Apple."
  - iCloud.com access is off by default. If it is enabled, the browser gets "temporary access to data-specific encryption keys provided by your device".
- **Photos.** — [Apple Photos & Privacy](https://www.apple.com/legal/privacy/data/en/photos/)
  - Faces and scenes are analysed on the device.
  - When you add a name in the People & Pets album, "their name and face will appear in Photos across all your iCloud-enabled devices".
  - The device "privately matches places in your photos to a global index Apple maintains on our servers".
  - Enhanced Visual Search applies "homomorphic encryption and differential privacy, and use[s] an OHTTP relay". That makes it a private server-side lookup, not a user-data index.

### Inferences
- **Signal and WhatsApp.** Both keep message history on the device, so search is local full-text search over the local database. There is no server index and nothing to sync. This is inferred; I fetched no official document for WhatsApp.
- **KBFS.** The KBFS index already lives in KBFS's encrypted block and metadata format, and only the server addresses are local. Pointing them at the real servers would give a synced, server-stored encrypted index, which is architecturally the target design. Keybase chose not to do this; I found no stated reason.
- **Skiff is the whole-blob pattern.** It is one compressed and encrypted object holding the whole index, rewritten at most every 30 s. Stored on a server, that object's size and rewrite timing would be the only leakage. Compression before encryption would make it a candidate for the length side channel in §6.
- **Apple.** Under ADP, iCloud Drive file names and checksums remain under keys Apple holds. Server-side search over names is therefore technically possible even with ADP; I found no documentation of whether Apple does it.

### Gaps
- No official Signal, WhatsApp or Element documentation on search internals was fetched. Seshat's use of Tantivy is unverified.
- CryptPad (whether it searches content or titles only, and whether locally) and Standard Notes internals were not researched or found in primary sources.
- Apple does not document how People and face data syncs, or whether that sync is end-to-end encrypted without ADP. Sources conflict: a Viallo blog says yes, a Vaultaire guide says no.

## 4. E2EE products that keep an encrypted index (or derived search data) server-side and sync it across devices

### Takeaway
I found only one clearly documented production example: Ente Photos. It computes ML embeddings on the device, compresses and encrypts them with each file's key, stores them in object storage, and lets new devices pull them instead of reindexing.

Apple syncs People names and faces across devices, but does not document the mechanism. Google's patented Gmail-style design keeps a server-side SSE index (searchable symmetric encryption, §5), which is a different model with query leakage. I found no evidence that it is deployed.

I found no E2EE mail or chat product that syncs a text index as encrypted objects.

### Cited Findings
**Ente** — [Ente ML page](https://ente.com/ml/)
- **On-device indexing.** Models run "locally on the user's device" with ONNX Runtime. Indexes include "both the image embedding and any face embeddings".
- **Server storage.** "All indexes are stored locally. They also get encrypted and stored on the server." "The information is compressed lossless and encrypted using the file key before being sent to our object storage."
- **Sync.** "The derived information is synced E2EE across platforms." "Each client pulls any existing indexes from Ente's server before indexing locally." A new device "will pull the information from the Ente server instead of having to derive everything again". Indexing can run on "more powerful devices, which can then be used by weaker devices".
- **Person entities.** Clusters are computed locally. Named or edited clusters are "encrypted as a person entity and stored on the server".
- **Search.** The text query goes through the text encoder and is compared locally against "all the image embeddings from the database".
- **Model size.** The text encoder was shrunk by about 70%.
- An earlier Ente desktop beta post said indexes were "currently not synced", so syncing came later. — [Ente desktop ML beta](https://ente.com/blog/desktop-ml-beta/)

**Google: "Encrypted search system design for email client-side encryption"** — [US 11,308,224](https://patents.google.com/patent/US11308224), [EP 4074003 B1](https://data.epo.org/gpi/EP4074003B1)
- **Filing.** Assigned to Google LLC; inventors Kevin Yeo, Ahmet Erhan Nergiz, Laetitia Estelle Baudoin, Nicolas Lidzborski and Sarvar Patel. Filed 2019-12-13, granted 2022-04-19; EP B1 granted 2023-04-05.
- **What the server stores.** An encrypted index of (keyword-hash, encrypted email ID) entries, an optional encrypted count table (bucketized, or downloaded by the client), encrypted metadata, and a deletion index.
- **Search tokens.** A delegatable PRF (DPRF) tree is built per keyword, with leaves indexed by keyword count. The client delegates a subtree so the server can evaluate only those leaves.
- **Adding mail.** The client increments the keyword count and sends a hash pair.
  - Only a probabilistic subset of new keywords enters the count table (1 in 50); otherwise a random count is used, to hide rare keywords.
  - Unopened received emails are not indexed, so senders can still revoke them.
- **Stated leakage.** The server still learns search patterns over time. Documents that share a token reveal that they share a keyword. Bucketization limits frequency leakage to groups of keywords.
- **Deployment.** Press coverage of the 2022 Gmail client-side encryption (CSE) beta said users could not search the body of encrypted messages. — [Android Police](https://www.androidpolice.com/gmail-client-side-encryption-beta-web/), [MediaNama](https://www.medianama.com/2022/12/223-gmail-workspace-client-side-encryption/) (secondary; the exact quote's source among these is unverified)

**ZeroDB**
- "ZeroDB is an end-to-end encrypted database that enables clients to operate on (search, sort, query, and share) encrypted data… query logic and encryption keys are pushed client-side". It offers "full-text search, sort, and range queries". — [ZeroDB white paper, arXiv:1602.07168](https://arxiv.org/abs/1602.07168)

### Inferences
- **Ente as the nearest analog.** Ente is the closest production match to "index stored server-side as ordinary encrypted objects, written by any client, read by all". Two differences matter:
  - The derived data is per file, encrypted with that file's key, so the server sees one derived-data object per file.
  - Search data that is per file can be updated without conflicts. A single per-repo inverted index needs merge or compaction when several clients commit concurrently.
- **Per-file leakage in Ente.** The size of each derived-data object probably correlates with the number of faces found, since face embeddings are fixed-length vectors. Ente does not document this.
- **Fetching part of a server-side index leaks access patterns.** ZeroDB-style designs keep query logic on the client but fetch parts of a server-side index on demand. The server then sees which index objects each query touches. Downloading the whole index, as the target design does, avoids this entirely.
- **The target design's leakage is much smaller than Google's.** Google's design leaks search and access patterns because the server takes part in every query. The target design never involves the server in a search, so its leakage reduces to index object sizes and update timing (§6).

### Gaps
- No evidence on whether Google's design shipped in Gmail CSE. Google's current Workspace documentation was not fetched.
- I did not verify that ZeroDB is defunct, or the details of its index layout (I recall server-stored encrypted B-tree buckets, but did not verify this).
- Apple's People sync mechanism and its encryption are undocumented in the pages fetched.
- I may have missed niche products: Proton Drive search, MEGA, Filen and Cryptee were not checked.

## 5. Server-side encrypted search: CryptDB, Mylar, SSE schemes, and what leakage-abuse attacks recover

### Takeaway
Server-assisted encrypted search always leaks something:
- the search pattern (which queries are equal),
- the access pattern (which documents match),
- volumes (how many results),
- and in CryptDB-style designs, equality and order of whole columns.

Attacks turn this leakage into recovered queries and data when the attacker has prior knowledge or can inject documents. Forward and backward privacy reduce what updates and deletions leak, but leave search and access patterns. Downloading the whole index removes search and access patterns entirely, at the cost of bandwidth.

### Cited Findings
**Leakage taxonomy and system classes** — [Fuller et al., "SoK: Cryptographically Protected Database Search", IEEE S&P 2017, arXiv:1703.02014](https://arxiv.org/abs/1703.02014)
- **What schemes leak.** Typically query equality (the "search pattern") and the "identifiers of data items returned across multiple queries (often called access patterns)".
- **CryptDB.** It handles query types with a layered "onion" approach. "Once a column is used in a query, CryptDB reveals statistics about the entire dataset's value on this column."
- **Blind Seer and OSPIR-OXT.** They "leak information to the server but primarily on data returned by the query". OSPIR-OXT supports boolean queries.
- **Snapshot vs persistent attackers.** Legacy schemes such as deterministic or order-preserving encryption leak about the whole database even to a snapshot attacker. Custom SSE schemes reveal information mainly during queries or updates, so they need a persistent attacker.
- **Forward privacy.** The SoK credits Stefanov et al. with showing how to achieve it.
- **Count attack (Cash et al.).** It "performs well if the keyword universe size is at most 5000", but needs a large known fraction of the data: with 80% known, the keyword recovery rate is 40%.
- **Injection (Zhang et al.).** About "nine records for a universe of 5000 keywords" suffice. In the limited-keywords setting, 40% leaked data gives 40% recovery.
- **Kellaris et al.** Their attack works even on oblivious ("Obliv") schemes, but needs smaller databases and keyword universes.

**Primary papers**
- **Cash, Grubbs, Perry, Ristenpart, "Leakage-Abuse Attacks Against Searchable Encryption" (CCS 2015).** It characterizes the leakage of commercial products and academic schemes, models attackers by their prior knowledge, evaluates query recovery and plaintext recovery, and includes "realistic active attacks". — [ePrint 2016/718](https://eprint.iacr.org/2016/718)
- **Zhang, Katz, Papamanthou, "All Your Queries Are Belong to Us" (USENIX Security 2016).** — [paper PDF](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_zhang.pdf), [ePrint 2016/172](https://eprint.iacr.org/2016/172)
  - Injecting `log |K|` files recovers any query keyword by binary search over the keyword universe K. A cap of T keywords per file forces `|K|/2T · log |K|` files.
  - Recovering a single token takes "log 2T = 9 files", and succeeds "about 70% of the time once only 20% of the files are leaked, and achieving 30% recovery rate even when given only 1% of the files". The Cash et al. attack "recovers a keyword with probability less than 20% even when 95% of the client's files are leaked".
  - "Forward privacy means that the server cannot tell if a newly inserted file matches previous search queries… Our work thus highlights the importance of forward privacy in any real-world deployment."
- **Kellaris, Kollios, Nissim, O'Neill, "Generic Attacks on Secure Outsourced Databases" (CCS 2016).** Generic reconstruction attacks for range queries using only access-pattern or communication-volume leakage. They apply even to systems built on ORAM or homomorphic encryption, and recover every record's secret attribute once enough queries have been seen. — [Harvard Privacy Tools](https://privacytools.seas.harvard.edu/publications/generic-attacks-secure-outsourced-databases)
  - The volume attack is reported to need about O(N⁴) queries with uniform queries, where N is the domain size, and fewer for dense databases. This comes from a search excerpt and is not checked against the PDF.
- **Naveed, Kamara, Wright, "Inference Attacks on Property-Preserving Encrypted Databases" (CCS 2015).** Plaintext recovered from columns under deterministic (DTE) and order-preserving (OPE) encryption, using frequency analysis, sorting, combinatorial optimization and public auxiliary data. — [Microsoft Research](https://www.microsoft.com/en-us/research/publication/inference-attacks-property-preserving-encrypted-databases/)
  - The study used patient records from 200 US hospitals. Press reported recovery of OPE attributes (age, severity) for more than 80% of records at 95% of hospitals. — [Healthcare IT News](https://www.healthcareitnews.com/news/even-encryption-emr-data-risk) (press figure, unverified against the paper)
  - The targets were CryptDB-style systems; CryptDB's authors disputed the findings. — [The Register](https://www.theregister.com/2015/09/11/encrypted_database_security/)
- **CryptDB (SOSP 2011).** — [paper](https://people.csail.mit.edu/nickolai/papers/raluca-cryptdb.pdf)
- **Mylar, "Building Web Applications on Top of Encrypted Data Using Mylar" (NSDI 2014).** — [USENIX](https://www.usenix.org/conference/nsdi14/technical-sessions/presentation/popa)
- **Grubbs, McPherson, Naveed, Ristenpart, Shmatikov, "Breaking Web Applications Built On Top of Encrypted Data" (CCS 2016).** Mylar-based apps reveal users' data and queries to passive and active malicious servers, and Mylar is generically insecure against active attacks because of design flaws. Attacks on ShadowCrypt recovered hundreds of the most frequent keywords. — [ePrint 2016/920](https://eprint.iacr.org/2016/920), [summary by The Morning Paper](https://blog.acolyer.org/2016/11/15/breaking-web-applications-built-on-top-of-encrypted-data/)
- **Bost, "Σoφoς (Sophos): Forward Secure Searchable Encryption" (CCS 2016).** Forward private: "the update procedure does not leak if a newly inserted element matches previous search queries". It "only relies on trapdoor permutations" and needs no ORAM. — [ePrint 2016/728](https://eprint.iacr.org/2016/728)
- **Bost, Minaud, Ohrimenko, "Forward and Backward Private Searchable Encryption from Constrained Cryptographic Primitives" (CCS 2017).** The first formal treatment of backward privacy: deleted results should stay hidden from the server. It defines several flavours, and builds schemes from constrained PRFs and puncturable encryption. — [ePrint 2017/805](https://eprint.iacr.org/2017/805)
- **Backward-privacy types.** Type-I to Type-III are "ordered from most to least secure". Chamani et al.'s CCS 2018 schemes: Mitra is Type-II and "the fastest and easiest to implement"; Orion is Type-I; Horus has fewer round trips but is Type-III. — [HKUST thesis summary](https://lbezone.hkust.edu.hk/rse/?p=59859), [paper record](https://www.aminer.org/pub/5bdc315017c44a1f58a059df/new-constructions-for-forward-and-backward-private-symmetric-searchable-encryption)
  - A later paper shows that Mitra's backward privacy can be downgraded from Type-II to Type-III. — [Korea Univ. record](https://pure.korea.ac.kr/en/publications/downgrading-backward-privacy-of-searchable-encryption/)

### Inferences
- **Leakage hierarchy.**
  - Deterministic or order-preserving encryption, as in CryptDB, leaks to a snapshot attacker.
  - Classic SSE (Curtmola-style) and OXT leak search and access patterns to a persistent attacker.
  - Forward-private dynamic SSE (Sophos, Diana) hides whether new documents match earlier queries.
  - Backward-private schemes (Janus, Mitra, Orion) also hide deleted matches.
  - Volume-hiding or ORAM-based schemes leave little beyond volumes.
  - The target design ("download everything, search locally") sits beyond all of these. The server never sees queries, so it learns no search pattern, access pattern or result volume. What remains is total index size and the write pattern.
- **Injection attacks still matter for the target design.** The precondition, getting content committed, is weaker in a repo store than in email. But a malicious collaborator, an imported dependency or a mirrored upstream can inject content. Without queries to observe, injection can only exploit how index sizes change (§6).
- **SSE's real benefit is bandwidth.** SSE lets a client search without holding the whole index, i.e. O(result) bandwidth. That matters only once the index is too large to download, which is the scale threshold to watch.

### Gaps
- **Not re-fetched this session, though cited widely:**
  - Curtmola, Garay, Kamara, Ostrovsky (2006, [ePrint 2006/210](https://eprint.iacr.org/2006/210)), which introduced formal SSE definitions and search/access-pattern leakage.
  - Cash et al. OXT (CRYPTO 2013, [ePrint 2013/169](https://eprint.iacr.org/2013/169)).
  - Islam, Kuzu, Kantarcioglu (NDSS 2012), the IKK attack.
- **Unverified scheme-to-type mapping** from my own recollection: Diana forward-private only; Dianadel and Janus Type-III; Fides Type-II; Moneta Type-I via ORAM. Also unverified: Sophos supports additions only. The ePrint PDFs were blocked (403/Cloudflare), so these were not checked.
- Exact count-attack recovery curves from Cash et al. 2015 and the exact query complexities from Kellaris et al. could not be pulled from the primary PDFs.
- Volume-attack follow-ups were not fetched: Grubbs et al. "Pump up the Volume" (CCS 2018) and "Learning to Reconstruct" (S&P 2019); Blackstone, Kamara, Moataz, "Revisiting Leakage Abuse Attacks" (NDSS 2020); and volume-hiding multimaps (Kamara–Moataz; Patel et al.).

## 6. Leakage when the index is stored as encrypted blobs: object sizes, update timing, padding

### Takeaway
When the server stores the index only as opaque encrypted objects and never sees queries, it learns only:
- object sizes and how they grow,
- when and how often each object is rewritten,
- and which client writes it.

The known sharp edges are three. Compressing before encrypting turns size into a content oracle when an attacker can inject data (DBREACH). Exact sizes fingerprint content. Per-update deltas reveal how much each update added. The documented countermeasures are padding to buckets (power-of-two as in KBFS, or Padmé), avoiding compression of attacker-influenced data, and batching or fixing the update cadence.

### Cited Findings
- **DBREACH (Hogan, Michalevsky, Eskandarian, IEEE S&P 2023).** — [paper](https://crypto.unc.edu/papers/dbreach.pdf), [Infosecurity coverage of the Black Hat 2021 talk](https://www.infosecurity-magazine.com/news/bhusa-researchers-reveal-dbreach/)
  - Compression side-channel attacks on InnoDB (MariaDB/MySQL) and WiredTiger (MongoDB) work on tables that are compressed and encrypted, using only approximate ciphertext sizes read from file sizes on disk.
  - With the ability to insert and update rows, the attacks detect whether a random string is in a table with more than 90% accuracy, and extract 10-character random strings with more than 95% success.
  - The authors: "The only foolproof method for preventing this attack is to turn off compression."
  - Follow-up attacks (G-DBREACH: Ghost, Group and Gallop) need fewer updates. — [G-DBREACH](https://crypto.unc.edu/papers/gdbreach.pdf)
- **PURBs and Padmé (Nikitin et al., PETS 2019).** — [arXiv:1806.03160](https://arxiv.org/abs/1806.03160)
  - Padmé padding limits what length leaks to "O(log log M) bits" for ciphertexts of maximum length M, with overhead "at most 12% and decreasing with" size.
  - It cuts the share of objects uniquely identifiable by size "from 83% to 3% for 56k Ubuntu packages, from 87% to 3% for 191k Youtube videos, from 45% to 8%" for a hard-drive user-files dataset, and "from 68% to 6%" for websites from the Alexa top 1M list.
  - "This much stronger leakage protection incurs an average space overhead of only 3%."
- **KBFS block padding.** Every KBFS block, including the KBFS search index's blocks, is padded with `PadBlock` to `powerOfTwoEqualOrGreater(len)` plus a 4-byte length prefix before encryption. — [kbfscrypto/pad.go](https://github.com/keybase/client/blob/HEAD/go/kbfs/kbfscrypto/pad.go)
  - The search indexer notes that `DiskUsage` "is the encoded, padded size". — [kbfs/search/indexer.go](https://github.com/keybase/client/blob/HEAD/go/kbfs/search/indexer.go)
- **Real update patterns.**
  - Skiff rewrote the entire compressed and encrypted index blob, debounced, at most every 30 s. — [searchIndex.ts](https://github.com/skiff-org/skiff-apps/blob/HEAD/libs/skiff-front-search/src/searchIndex.ts)
  - Keybase batches index flushes to avoid "wasteful re-encryption of hot tokens". — [storage.go](https://github.com/keybase/client/blob/HEAD/go/chat/search/storage.go)
  - Ente compresses each file's derived data and encrypts it with that file's key. — [Ente ML](https://ente.com/ml/)
- **Persistent attackers and injection.**
  - Leakage that appears only during updates is exploitable only by a persistent attacker, not one holding a single snapshot. — [SoK, arXiv:1703.02014](https://arxiv.org/abs/1703.02014)
  - File-injection attacks exploit attacker-controlled inserts. — [Zhang et al. 2016](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_zhang.pdf)

### Inferences
- **What the server learns in the target design.**
  - The size history of the index object or objects tracks corpus growth: distinct terms and postings.
  - Each commit's index delta reveals how much indexable text that commit added. Commit object sizes already reveal much of this, so the extra leakage is small unless the dictionary or term statistics are stored separately.
  - Timing and authorship of index writes mirror the commit timing the server already sees.
- **The most concrete risk is a compression oracle.**
  - Suppose the index, or a shared segment, is compressed before encryption, and an attacker can get content committed. The attacker can then test whether a guessed string or term is already in the index by watching the size delta, as in DBREACH.
  - A dictionary-growth oracle has the same shape: a new distinct term grows the size more than a repeated one.
  - Mitigations:
    - pad each encrypted index object to Padmé or power-of-two buckets;
    - compress per document rather than across documents, or not at all;
    - or batch rebuilds so that one delta mixes many commits.
- **Deterministic encryption must stay inside the blob.** Deterministic term ciphertexts (Tuta-style) are harmless inside one encrypted blob. As separately addressable server objects (one per term or posting row) they would recreate SSE-style leakage: term-frequency histograms, co-occurrence through shared update timing, and access patterns if fetched per query.
- **Segmenting the index.** An append-only log of segments plus periodic compaction (the Lucene/FTS5 style) keeps "download everything" free of query leakage, as long as clients fetch segments by sync position, never by query.

### Gaps
- No product documents padding for its encrypted index blobs other than KBFS's generic block padding.
- No measurements of how index-size deltas correlate with content for code or text repositories.
- No study found of compression oracles against encrypted search indexes specifically; I am extrapolating from DBREACH.

## 7. Deletion and the "right to be forgotten" (removing a document's terms from the index)

### Takeaway
The local-index products delete postings physically or semi-physically:
- Tuta's IndexedDB index removes entries and rewrites the rows.
- Skiff discarded entries, vacuumed, then re-encrypted the whole blob.
- Tuta's FTS5 index uses contentless-delete, but by default leaves recoverable delete-markers until merges.

Proton deletes the index only when browser data is cleared; disabling search keeps it. In SSE, deletion is a leakage problem (backward privacy), and many schemes keep deleted entries on the server until a rebuild.

For a versioned store, the deeper problem is that history keeps old index versions. Removing a document's terms from the latest index does not forget them.

### Cited Findings
- **Tuta, IndexedDB backend.**
  - `_deleteIndexedInstance` deletes the item's ElementData. For each affected metadata row it finds entries "by hash of the encrypted ID" and removes their byte ranges (`removeBinaryBlockRanges`). It deletes the row if every entry was removed, and rewrites or deletes the encrypted metadata row. Moves only update the listId. — [IndexerCore.ts](https://github.com/tutao/tutanota/blob/HEAD/src/applications/mail-app/workerUtils/index/IndexerCore.ts)
  - The reverse map exists so deletes do not need a scan. — [SearchTypes.ts](https://github.com/tutao/tutanota/blob/HEAD/src/applications/common/api/worker/search/SearchTypes.ts)
- **Tuta, FTS5 backend.** `mail_index` is `content=''` with `contentless_delete=1`. — [OfflineStoragePersistence.ts](https://github.com/tutao/tutanota/blob/HEAD/src/applications/mail-app/workerUtils/index/OfflineStoragePersistence.ts)
- **What SQLite documents about FTS5 deletion.** — [SQLite FTS5 docs](https://sqlite.org/fts5.html)
  - Contentless-delete tables (available from 3.43.0) support DELETE and "INSERT OR REPLACE INTO".
  - By default, old full-text entries remain "until they are eventually removed by merge operations… Anyone with access to the database can use these entries to trivially reconstruct the contents of deleted FTS5 table rows."
  - With `secure-delete=1` the entries are actually removed. Protecting against someone with the raw file also needs `PRAGMA secure_delete = 1`.
  - The default is 0.
- **Proton.** Clearing browser data erases the index. Disabling the feature does not ("The index won't be erased if you do this"). Logout keeps it. — [Proton support](https://proton.me/support/search-message-content)
- **Skiff.** Removal calls `miniSearch.discard(id)`, then `vacuum()` before the whole index is re-serialized, re-encrypted and saved. — [searchIndex.ts](https://github.com/skiff-org/skiff-apps/blob/HEAD/libs/skiff-front-search/src/searchIndex.ts)
- **Google's patented design.** On deletion the client decrements the counts and sends hash pairs so the server removes the matching entries. The server may also keep a list of deleted IDs, filter them out of results, and compact the index later. — [US 11,308,224](https://patents.google.com/patent/US11308224)
- **Backward privacy in SSE.** Backward privacy asks that deleted documents' results stay hidden from the server. The concept had "been overlooked" until Bost–Minaud–Ohrimenko 2017. — [ePrint 2017/805](https://eprint.iacr.org/2017/805)
  - Type-I is strongest, Type-III weakest. — [HKUST summary](https://lbezone.hkust.edu.hk/rse/?p=59859)
- **Ente.** Derived data is encrypted with each file's key. — [Ente ML](https://ente.com/ml/)

### Inferences
- **Tuta's FTS5 index.** I found no code hits for `secure-delete`. Assuming the default holds, deleted mail is recoverable from the FTS5 index by anyone with the SQLCipher key until segments merge. SQLCipher keeps the data from outsiders, but this falls short of "forgotten".
- **SSE deletion.** It is usually logical: tombstones or punctured keys, with ciphertexts kept until a rebuild. The physical ciphertexts persist on the server, and only cryptographic unreachability protects them.
- **What the target design needs.** Old index objects stay referenced by history, so they keep a document's terms after it is deleted. Real forgetting needs one of:
  - **Garbage collection.** The server is allowed to drop unreferenced old index objects, with the index kept out of the immutable commit DAG (for example a mutable or derived ref).
  - **Crypto-shredding.** Index objects are encrypted under per-epoch keys, and old epoch keys are destroyed after compaction.
  - **Rewriting history.** This is heavy-handed for a versioned store.

  The new index should also be rebuilt by compaction, not tombstoned, which mirrors FTS5's secure-delete and merge semantics.
- **Ente-style per-file keys.** Encrypting each document's index contribution under its own key makes deletion a key-deletion operation. That fits per-document search data well (embeddings) and fits a merged inverted index poorly.

### Gaps
- I found no product documentation describing how an E2EE search index honours erasure requests (for example GDPR Art. 17) beyond deleting local data.
- I did not verify what Proton's event-driven updates do on message deletion.
- I found no academic treatment of secure deletion for client-side encrypted indexes stored in versioned or content-addressed stores.
