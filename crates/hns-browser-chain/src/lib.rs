use hns_core::hash::Hash;
use hns_core::pow::{Chainwork, PowError, Target, target_for_work, verify_pow};
use hns_core::{BlockHeader, Height};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;
use thiserror::Error;

const MAINNET_POW_BITS: u32 = 0x1c00ffff;
const MAINNET_TARGET_SPACING: u64 = 10 * 60;
const MAINNET_BLOCKS_PER_DAY: u32 = 144;
const MAINNET_MIN_ACTUAL_TIMESPAN: u64 = 36 * MAINNET_TARGET_SPACING;
const MAINNET_MAX_ACTUAL_TIMESPAN: u64 = 576 * MAINNET_TARGET_SPACING;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredHeader {
    pub hash: Hash,
    pub header: BlockHeader,
    pub height: Height,
    pub chainwork: Chainwork,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeaderCheckpoint {
    pub height: Height,
    pub hash: Hash,
}

pub trait HeaderStore {
    fn get_header(&self, hash: Hash) -> Option<StoredHeader>;
    fn put_header(&mut self, header: StoredHeader) -> Result<(), ChainError>;
    fn put_headers(&mut self, headers: &[StoredHeader]) -> Result<(), ChainError> {
        for header in headers {
            self.put_header(header.clone())?;
        }
        Ok(())
    }
    fn best_hash(&self) -> Option<Hash>;
    fn canonical_hash(&self, height: Height) -> Option<Hash>;
    fn promote_canonical_tip(&mut self, header: &StoredHeader) -> Result<(), ChainError>;
    fn promote_canonical_tips(&mut self, headers: &[StoredHeader]) -> Result<(), ChainError> {
        for header in headers {
            self.promote_canonical_tip(header)?;
        }
        Ok(())
    }
    fn replace_canonical_chain(&mut self, headers: &[StoredHeader]) -> Result<(), ChainError>;
}

#[derive(Default)]
pub struct MemoryHeaderStore {
    headers: HashMap<Hash, StoredHeader>,
    canonical: HashMap<u32, Hash>,
    best: Option<Hash>,
}

pub struct SqliteHeaderStore {
    connection: Connection,
}

pub struct HeaderChain<S> {
    store: S,
    difficulty_policy: DifficultyPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DifficultyPolicy {
    Mainnet,
    Permissive,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ChainError {
    #[error("mainnet genesis header is invalid")]
    InvalidGenesisHeader,
    #[error("header parent is unknown")]
    UnknownParent,
    #[error("header already exists")]
    DuplicateHeader,
    #[error("best header is missing from store")]
    MissingBestHeader,
    #[error("header difficulty bits are invalid: got {actual:#010x}, expected {expected:#010x}")]
    InvalidDifficultyBits { actual: u32, expected: u32 },
    #[error("header difficulty window is invalid")]
    InvalidDifficultyWindow,
    #[error("header proof-of-work does not satisfy target")]
    InvalidProofOfWork,
    #[error("mainnet checkpoint mismatch at height {height}: got {actual}, expected {expected}")]
    InvalidCheckpoint {
        height: u32,
        actual: Hash,
        expected: Hash,
    },
    #[error("proof-of-work target error: {0}")]
    Pow(#[from] PowError),
    #[error("storage error: {0}")]
    Storage(String),
}

pub fn mainnet_checkpoint_hash(height: Height) -> Option<Hash> {
    let hash = match height.0 {
        1008 => checkpoint_hash("0000000000001013c28fa079b545fb805f04c496687799b98e35e83cbbb8953e"),
        2016 => checkpoint_hash("0000000000000424ee6c2a5d6e0da5edfc47a4a10328c1792056ee48303c3e40"),
        10_000 => {
            checkpoint_hash("00000000000001a86811a6f520bf67cefa03207dc84fd315f58153b28694ec51")
        }
        20_000 => {
            checkpoint_hash("0000000000000162c7ac70a582256f59c189b5c90d8e9861b3f374ed714c58de")
        }
        30_000 => {
            checkpoint_hash("0000000000000004f790862846b23c3a81585aea0fa79a7d851b409e027bcaa7")
        }
        40_000 => {
            checkpoint_hash("0000000000000002966206a40b10a575cb46531253b08dae8e1b356cfa277248")
        }
        50_000 => {
            checkpoint_hash("00000000000000020c7447e7139feeb90549bfc77a7f18d4ff28f327c04f8d6e")
        }
        56_880 => {
            checkpoint_hash("0000000000000001d4ef9ea6908bb4eb970d556bd07cbd7d06a634e1cd5bbf4e")
        }
        61_043 => {
            checkpoint_hash("00000000000000015b84385e0307370f8323420eaa27ef6e407f2d3162f1fd05")
        }
        100_000 => {
            checkpoint_hash("000000000000000136d7d3efa688072f40d9fdd71bd47bb961694c0f38950246")
        }
        130_000 => {
            checkpoint_hash("0000000000000005ee5106df9e48bcd232a1917684ac344b35ddd9b9e4101096")
        }
        160_000 => {
            checkpoint_hash("00000000000000021e723ce5aedc021ab4f85d46a6914e40148f01986baa46c9")
        }
        200_000 => {
            checkpoint_hash("000000000000000181ebc18d6c34442ffef3eedca90c57ca8ecc29016a1cfe16")
        }
        225_000 => {
            checkpoint_hash("00000000000000021f0be013ebad018a9ef97c8501766632f017a778781320d5")
        }
        258_026 => {
            checkpoint_hash("0000000000000004963d20732c58e5a91cb7e1b61ec6709d031f1a5ca8c55b95")
        }
        _ => return None,
    };

    Some(hash)
}

pub fn mainnet_sync_checkpoints() -> Vec<HeaderCheckpoint> {
    [50_000_u32, 100_000, 160_000, 200_000, 225_000, 258_026]
        .into_iter()
        .filter_map(|height| {
            let height = Height(height);
            mainnet_checkpoint_hash(height).map(|hash| HeaderCheckpoint { height, hash })
        })
        .collect()
}

fn checkpoint_hash(hex_value: &str) -> Hash {
    Hash::from_hex(hex_value).expect("valid mainnet checkpoint hash")
}

impl HeaderStore for MemoryHeaderStore {
    fn get_header(&self, hash: Hash) -> Option<StoredHeader> {
        self.headers.get(&hash).cloned()
    }

    fn put_header(&mut self, header: StoredHeader) -> Result<(), ChainError> {
        if self.headers.contains_key(&header.hash) {
            return Err(ChainError::DuplicateHeader);
        }

        self.headers.insert(header.hash, header);
        Ok(())
    }

    fn best_hash(&self) -> Option<Hash> {
        self.best
    }

    fn canonical_hash(&self, height: Height) -> Option<Hash> {
        self.canonical.get(&height.0).copied()
    }

    fn promote_canonical_tip(&mut self, header: &StoredHeader) -> Result<(), ChainError> {
        if !self.headers.contains_key(&header.hash) {
            return Err(ChainError::MissingBestHeader);
        }

        self.canonical.insert(header.height.0, header.hash);
        self.best = Some(header.hash);
        Ok(())
    }

    fn replace_canonical_chain(&mut self, headers: &[StoredHeader]) -> Result<(), ChainError> {
        let Some(tip) = headers.last() else {
            return Err(ChainError::MissingBestHeader);
        };
        if headers
            .iter()
            .any(|header| !self.headers.contains_key(&header.hash))
        {
            return Err(ChainError::MissingBestHeader);
        }

        self.canonical.clear();
        for header in headers {
            self.canonical.insert(header.height.0, header.hash);
        }
        self.best = Some(tip.hash);
        Ok(())
    }
}

impl MemoryHeaderStore {
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }
}

impl SqliteHeaderStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ChainError> {
        let connection =
            Connection::open(path).map_err(|error| ChainError::Storage(error.to_string()))?;
        Self::from_connection(connection)
    }

    pub fn in_memory() -> Result<Self, ChainError> {
        let connection =
            Connection::open_in_memory().map_err(|error| ChainError::Storage(error.to_string()))?;
        Self::from_connection(connection)
    }

    pub fn from_connection(connection: Connection) -> Result<Self, ChainError> {
        let store = Self { connection };
        store.initialize()?;
        Ok(store)
    }

    pub fn snapshot_to(&self, path: impl AsRef<Path>) -> Result<(), ChainError> {
        let path = path.as_ref();
        let sqlite_path = sqlite_path_text(path, "snapshot destination")?;
        match std::fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(ChainError::Storage(
                    "snapshot destination already exists".to_owned(),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(ChainError::Storage(format!(
                    "could not inspect snapshot destination: {error}"
                )));
            }
        }

        self.connection
            .execute("VACUUM INTO ?1", params![sqlite_path])
            .map_err(|error| ChainError::Storage(format!("could not create snapshot: {error}")))?;
        Ok(())
    }

    pub fn sync_generation(&self) -> Result<u64, ChainError> {
        read_sync_generation(&self.connection)
    }

    pub fn set_sync_generation(&mut self, generation: u64) -> Result<(), ChainError> {
        self.connection
            .execute(
                "
                INSERT INTO chain_state(key, value)
                VALUES ('sync_generation', ?1)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                ",
                params![generation.to_le_bytes().as_slice()],
            )
            .map_err(|error| {
                ChainError::Storage(format!("could not store sync generation: {error}"))
            })?;
        Ok(())
    }

    /// Marks a private snapshot as a conditional-publication stage.
    ///
    /// Once enabled, an SQLite trigger journals every subsequently inserted
    /// header in the same transaction as that header. Conditional publication
    /// can therefore validate and copy only the staged delta rather than
    /// rescanning the complete historical header table while the live store is
    /// exclusively locked.
    pub fn begin_snapshot_publication_delta(
        &mut self,
        expected_sync_generation: u64,
        expected_best_hash: Option<Hash>,
    ) -> Result<(), ChainError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| {
                ChainError::Storage(format!(
                    "could not begin snapshot delta initialization: {error}"
                ))
            })?;
        let actual_generation = read_sync_generation(&transaction)?;
        let actual_best_hash = read_best_hash(&transaction)?;
        if actual_generation != expected_sync_generation || actual_best_hash != expected_best_hash {
            return Err(ChainError::Storage(
                "snapshot delta baseline does not match the staged chain state".to_owned(),
            ));
        }
        transaction
            .execute("DELETE FROM snapshot_publication_baseline", [])
            .and_then(|_| transaction.execute("DELETE FROM snapshot_publication_new_headers", []))
            .map_err(|error| {
                ChainError::Storage(format!(
                    "could not clear snapshot publication delta: {error}"
                ))
            })?;
        transaction
            .execute(
                "
                INSERT INTO snapshot_publication_baseline(
                    singleton,
                    sync_generation,
                    best_hash
                )
                VALUES (1, ?1, ?2)
                ",
                params![
                    expected_sync_generation.to_le_bytes().as_slice(),
                    expected_best_hash.map(|hash| hash.as_bytes().to_vec()),
                ],
            )
            .map_err(|error| {
                ChainError::Storage(format!("could not store snapshot delta baseline: {error}"))
            })?;
        transaction.commit().map_err(|error| {
            ChainError::Storage(format!("could not commit snapshot delta baseline: {error}"))
        })
    }

    pub fn publish_snapshot_from(&mut self, path: impl AsRef<Path>) -> Result<(), ChainError> {
        self.publish_snapshot(path.as_ref(), None).map(|_| ())
    }

    pub fn publish_snapshot_from_if_current(
        &mut self,
        path: impl AsRef<Path>,
        expected_sync_generation: u64,
        expected_best_hash: Option<Hash>,
    ) -> Result<bool, ChainError> {
        self.publish_snapshot(
            path.as_ref(),
            Some((expected_sync_generation, expected_best_hash)),
        )
    }

    fn publish_snapshot(
        &mut self,
        path: &Path,
        expected_live_state: Option<(u64, Option<Hash>)>,
    ) -> Result<bool, ChainError> {
        const STAGED_DATABASE: &str = "hns_chain_publish_stage";

        let sqlite_path = sqlite_path_text(path, "snapshot source")?;
        let metadata = std::fs::metadata(path).map_err(|error| {
            ChainError::Storage(format!("could not inspect snapshot source: {error}"))
        })?;
        if !metadata.is_file() {
            return Err(ChainError::Storage(
                "snapshot source is not a regular file".to_owned(),
            ));
        }

        self.connection
            .execute(
                &format!("ATTACH DATABASE ?1 AS {STAGED_DATABASE}"),
                params![sqlite_path],
            )
            .map_err(|error| ChainError::Storage(format!("could not attach snapshot: {error}")))?;

        let publication = (|| {
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|error| {
                    ChainError::Storage(format!("could not begin snapshot publication: {error}"))
                })?;

            if let Some((expected_generation, expected_best_hash)) = expected_live_state {
                let live_generation = read_sync_generation(&transaction)?;
                let live_best_hash = read_best_hash(&transaction)?;
                if live_generation != expected_generation || live_best_hash != expected_best_hash {
                    return Ok(false);
                }
                validate_snapshot_publication_baseline(
                    &transaction,
                    STAGED_DATABASE,
                    expected_generation,
                    expected_best_hash,
                )?;
                publish_snapshot_delta(&transaction, STAGED_DATABASE)?;
            } else {
                publish_snapshot_full(&transaction, STAGED_DATABASE)?;
            }

            transaction.commit().map_err(|error| {
                ChainError::Storage(format!("could not commit snapshot publication: {error}"))
            })?;
            Ok(true)
        })();

        let detach = self
            .connection
            .execute_batch(&format!("DETACH DATABASE {STAGED_DATABASE}"))
            .map_err(|error| ChainError::Storage(format!("could not detach snapshot: {error}")));

        match publication {
            Err(error) => {
                let _ = detach;
                Err(error)
            }
            Ok(published) => detach.map(|()| published),
        }
    }

    fn initialize(&self) -> Result<(), ChainError> {
        self.connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|error| ChainError::Storage(error.to_string()))?;
        self.connection
            .execute_batch(
                "
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = NORMAL;
                PRAGMA foreign_keys = ON;

                CREATE TABLE IF NOT EXISTS headers_by_hash (
                    hash BLOB PRIMARY KEY NOT NULL,
                    height INTEGER NOT NULL,
                    chainwork TEXT NOT NULL,
                    header BLOB NOT NULL
                );

                CREATE INDEX IF NOT EXISTS headers_by_height
                    ON headers_by_hash(height);

                CREATE TABLE IF NOT EXISTS hash_by_height (
                    height INTEGER PRIMARY KEY NOT NULL,
                    hash BLOB NOT NULL,
                    FOREIGN KEY(hash) REFERENCES headers_by_hash(hash)
                );

                CREATE TABLE IF NOT EXISTS chain_state (
                    key TEXT PRIMARY KEY NOT NULL,
                    value BLOB NOT NULL
                );

                CREATE TABLE IF NOT EXISTS snapshot_publication_baseline (
                    singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
                    sync_generation BLOB NOT NULL,
                    best_hash BLOB
                );

                CREATE TABLE IF NOT EXISTS snapshot_publication_new_headers (
                    hash BLOB PRIMARY KEY NOT NULL
                );

                CREATE TRIGGER IF NOT EXISTS journal_snapshot_publication_header
                AFTER INSERT ON headers_by_hash
                WHEN EXISTS(
                    SELECT 1
                    FROM snapshot_publication_baseline
                    WHERE singleton = 1
                )
                BEGIN
                    INSERT OR IGNORE INTO snapshot_publication_new_headers(hash)
                    VALUES (NEW.hash);
                END;
                ",
            )
            .map_err(|error| ChainError::Storage(error.to_string()))
    }

    pub fn flush(self) -> Result<(), ChainError> {
        self.connection
            .close()
            .map_err(|(_, error)| ChainError::Storage(error.to_string()))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CanonicalTip {
    height: u32,
    hash: Hash,
}

fn validate_snapshot_publication_baseline(
    transaction: &Transaction<'_>,
    staged_database: &str,
    expected_generation: u64,
    expected_best_hash: Option<Hash>,
) -> Result<(), ChainError> {
    let encoded: Option<(Vec<u8>, Option<Vec<u8>>)> = transaction
        .query_row(
            &format!(
                "
                SELECT sync_generation, best_hash
                FROM {staged_database}.snapshot_publication_baseline
                WHERE singleton = 1
                "
            ),
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| {
            ChainError::Storage(format!("could not read snapshot delta baseline: {error}"))
        })?;
    let Some((generation, best_hash)) = encoded else {
        return Err(ChainError::Storage(
            "conditional snapshot is missing its publication delta baseline".to_owned(),
        ));
    };
    let generation: [u8; 8] = generation.try_into().map_err(|_| {
        ChainError::Storage("snapshot delta generation has an invalid length".to_owned())
    })?;
    let generation = u64::from_le_bytes(generation);
    let best_hash = best_hash
        .map(|encoded| {
            Hash::from_slice(&encoded).map_err(|error| {
                ChainError::Storage(format!("snapshot delta best hash is invalid: {error}"))
            })
        })
        .transpose()?;
    if generation != expected_generation || best_hash != expected_best_hash {
        return Err(ChainError::Storage(
            "conditional snapshot delta baseline does not match the expected live state".to_owned(),
        ));
    }
    let staged_generation = read_sync_generation_in_schema(transaction, staged_database)?;
    if staged_generation <= expected_generation {
        return Err(ChainError::Storage(
            "conditional snapshot generation did not advance".to_owned(),
        ));
    }
    Ok(())
}

fn publish_snapshot_delta(
    transaction: &Transaction<'_>,
    staged_database: &str,
) -> Result<(), ChainError> {
    validate_journaled_headers(transaction, staged_database)?;

    transaction
        .execute(
            &format!(
                "
                INSERT OR IGNORE INTO main.headers_by_hash(
                    hash,
                    height,
                    chainwork,
                    header
                )
                SELECT staged.hash, staged.height, staged.chainwork, staged.header
                FROM {staged_database}.snapshot_publication_new_headers AS delta
                CROSS JOIN {staged_database}.headers_by_hash AS staged
                WHERE staged.hash = delta.hash
                "
            ),
            [],
        )
        .map_err(|error| {
            ChainError::Storage(format!("could not publish staged header delta: {error}"))
        })?;

    let live_tip = read_canonical_tip(transaction, "main")?;
    let staged_tip = read_canonical_tip(transaction, staged_database)?;
    let first_divergent_height =
        first_canonical_divergence(transaction, staged_database, live_tip, staged_tip)?;
    if let Some(first_divergent_height) = first_divergent_height {
        validate_staged_canonical_suffix(
            transaction,
            staged_database,
            first_divergent_height,
            staged_tip,
        )?;
        validate_staged_canonical_publication_coverage(
            transaction,
            staged_database,
            first_divergent_height,
        )?;
        transaction
            .execute(
                "DELETE FROM main.hash_by_height WHERE height >= ?1",
                params![first_divergent_height],
            )
            .map_err(|error| {
                ChainError::Storage(format!("could not replace canonical suffix: {error}"))
            })?;
        transaction
            .execute(
                &format!(
                    "
                    INSERT INTO main.hash_by_height(height, hash)
                    SELECT height, hash
                    FROM {staged_database}.hash_by_height
                    WHERE height >= ?1
                    ORDER BY height
                    "
                ),
                params![first_divergent_height],
            )
            .map_err(|error| {
                ChainError::Storage(format!("could not publish canonical suffix: {error}"))
            })?;
    }
    replace_chain_state_from_snapshot(transaction, staged_database)
}

fn validate_journaled_headers(
    transaction: &Transaction<'_>,
    staged_database: &str,
) -> Result<(), ChainError> {
    let missing_header: bool = transaction
        .query_row(
            &format!(
                "
                SELECT EXISTS(
                    SELECT 1
                    FROM {staged_database}.snapshot_publication_new_headers AS delta
                    LEFT JOIN {staged_database}.headers_by_hash AS staged
                        ON staged.hash = delta.hash
                    WHERE staged.hash IS NULL
                )
                "
            ),
            [],
            |row| row.get(0),
        )
        .map_err(|error| {
            ChainError::Storage(format!("could not validate staged header journal: {error}"))
        })?;
    if missing_header {
        return Err(ChainError::Storage(
            "snapshot header journal references a missing header".to_owned(),
        ));
    }

    let conflicting_header: bool = transaction
        .query_row(
            &format!(
                "
                SELECT EXISTS(
                    SELECT 1
                    FROM {staged_database}.snapshot_publication_new_headers AS delta
                    CROSS JOIN {staged_database}.headers_by_hash AS staged
                    CROSS JOIN main.headers_by_hash AS live
                    WHERE staged.hash = delta.hash
                      AND live.hash = staged.hash
                      AND (
                          staged.height != live.height
                          OR staged.chainwork != live.chainwork
                          OR staged.header != live.header
                      )
                )
                "
            ),
            [],
            |row| row.get(0),
        )
        .map_err(|error| {
            ChainError::Storage(format!(
                "could not validate staged header conflicts: {error}"
            ))
        })?;
    if conflicting_header {
        return Err(ChainError::Storage(
            "snapshot contains a journaled header that conflicts with live storage".to_owned(),
        ));
    }

    let mut statement = transaction
        .prepare(&format!(
            "
            SELECT staged.hash, staged.height, staged.chainwork, staged.header
            FROM {staged_database}.snapshot_publication_new_headers AS delta
            CROSS JOIN {staged_database}.headers_by_hash AS staged
            WHERE staged.hash = delta.hash
            "
        ))
        .map_err(|error| {
            ChainError::Storage(format!("could not inspect staged header journal: {error}"))
        })?;
    let headers = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })
        .map_err(|error| {
            ChainError::Storage(format!("could not query staged header journal: {error}"))
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            ChainError::Storage(format!("could not decode staged header journal: {error}"))
        })?;
    drop(statement);

    for (encoded_hash, height, encoded_chainwork, encoded_header) in headers {
        let hash = Hash::from_slice(&encoded_hash).map_err(|error| {
            ChainError::Storage(format!("journaled header hash is invalid: {error}"))
        })?;
        let header = BlockHeader::parse(&encoded_header).map_err(|error| {
            ChainError::Storage(format!("journaled header encoding is invalid: {error}"))
        })?;
        if header.hash() != hash {
            return Err(ChainError::Storage(
                "journaled header hash does not match its encoding".to_owned(),
            ));
        }
        if !verify_pow(hash, header.bits)? {
            return Err(ChainError::Storage(
                "journaled header does not satisfy proof of work".to_owned(),
            ));
        }
        let chainwork = Chainwork::from_hex(&encoded_chainwork)?;
        let expected_chainwork = if height == 0 {
            if header.prev_block != Hash::ZERO {
                return Err(ChainError::Storage(
                    "journaled genesis header has a nonzero parent".to_owned(),
                ));
            }
            Chainwork::from_bits(header.bits)?
        } else {
            let parent = read_header_metadata(transaction, staged_database, header.prev_block)?
                .ok_or_else(|| {
                    ChainError::Storage("journaled header parent is missing".to_owned())
                })?;
            if parent.0.checked_add(1) != Some(height) {
                return Err(ChainError::Storage(
                    "journaled header height does not follow its parent".to_owned(),
                ));
            }
            parent.1.checked_add(&Chainwork::from_bits(header.bits)?)
        };
        if chainwork != expected_chainwork {
            return Err(ChainError::Storage(
                "journaled header chainwork does not follow its parent".to_owned(),
            ));
        }
    }
    Ok(())
}

fn read_header_metadata(
    transaction: &Transaction<'_>,
    schema: &str,
    hash: Hash,
) -> Result<Option<(u32, Chainwork)>, ChainError> {
    let encoded: Option<(u32, String)> = transaction
        .query_row(
            &format!(
                "
                SELECT height, chainwork
                FROM {schema}.headers_by_hash
                WHERE hash = ?1
                "
            ),
            params![hash.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| {
            ChainError::Storage(format!("could not read staged header parent: {error}"))
        })?;
    encoded
        .map(|(height, chainwork)| Ok((height, Chainwork::from_hex(&chainwork)?)))
        .transpose()
}

fn read_canonical_tip(
    transaction: &Transaction<'_>,
    schema: &str,
) -> Result<Option<CanonicalTip>, ChainError> {
    let best_hash = read_best_hash_in_schema(transaction, schema)?;
    let maximum_height: Option<u32> = transaction
        .query_row(
            &format!("SELECT MAX(height) FROM {schema}.hash_by_height"),
            [],
            |row| row.get(0),
        )
        .map_err(|error| {
            ChainError::Storage(format!(
                "could not read {schema} canonical tip height: {error}"
            ))
        })?;
    let Some(best_hash) = best_hash else {
        if maximum_height.is_some() {
            return Err(ChainError::Storage(format!(
                "{schema} canonical index exists without a best hash"
            )));
        }
        return Ok(None);
    };
    let tip_height: Option<u32> = transaction
        .query_row(
            &format!(
                "
                SELECT header.height
                FROM {schema}.headers_by_hash AS header
                INNER JOIN {schema}.hash_by_height AS canonical
                    ON canonical.height = header.height
                   AND canonical.hash = header.hash
                WHERE header.hash = ?1
                "
            ),
            params![best_hash.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| {
            ChainError::Storage(format!(
                "could not validate {schema} canonical tip: {error}"
            ))
        })?;
    let Some(height) = tip_height else {
        return Err(ChainError::Storage(format!(
            "{schema} best hash is not its canonical tip"
        )));
    };
    if maximum_height != Some(height) {
        return Err(ChainError::Storage(format!(
            "{schema} best hash does not match the maximum canonical height"
        )));
    }
    Ok(Some(CanonicalTip {
        height,
        hash: best_hash,
    }))
}

fn first_canonical_divergence(
    transaction: &Transaction<'_>,
    staged_database: &str,
    live_tip: Option<CanonicalTip>,
    staged_tip: Option<CanonicalTip>,
) -> Result<Option<u32>, ChainError> {
    if live_tip == staged_tip {
        return Ok(None);
    }
    let (Some(live_tip), Some(staged_tip)) = (live_tip, staged_tip) else {
        return Ok(Some(0));
    };
    let mut height = live_tip.height.min(staged_tip.height);
    loop {
        let live_hash = read_canonical_hash(transaction, "main", height)?.ok_or_else(|| {
            ChainError::Storage("live canonical chain has a height gap".to_owned())
        })?;
        let staged_hash =
            read_canonical_hash(transaction, staged_database, height)?.ok_or_else(|| {
                ChainError::Storage("staged canonical chain has a height gap".to_owned())
            })?;
        if live_hash == staged_hash {
            return height
                .checked_add(1)
                .map(Some)
                .ok_or(ChainError::InvalidDifficultyWindow);
        }
        if height == 0 {
            return Err(ChainError::Storage(
                "snapshot canonical chain has no common genesis".to_owned(),
            ));
        }
        height -= 1;
    }
}

fn validate_staged_canonical_suffix(
    transaction: &Transaction<'_>,
    staged_database: &str,
    first_height: u32,
    staged_tip: Option<CanonicalTip>,
) -> Result<(), ChainError> {
    let expected_count = staged_tip
        .filter(|tip| tip.height >= first_height)
        .map(|tip| i64::from(tip.height - first_height) + 1)
        .unwrap_or(0);
    let actual_count: i64 = transaction
        .query_row(
            &format!(
                "
                SELECT COUNT(*)
                FROM {staged_database}.hash_by_height
                WHERE height >= ?1
                "
            ),
            params![first_height],
            |row| row.get(0),
        )
        .map_err(|error| {
            ChainError::Storage(format!("could not count staged canonical suffix: {error}"))
        })?;
    if actual_count != expected_count {
        return Err(ChainError::Storage(
            "snapshot canonical suffix is not contiguous".to_owned(),
        ));
    }
    let invalid_canonical_header: bool = transaction
        .query_row(
            &format!(
                "
                SELECT EXISTS(
                    SELECT 1
                    FROM {staged_database}.hash_by_height AS canonical
                    LEFT JOIN {staged_database}.headers_by_hash AS header
                        ON header.hash = canonical.hash
                    WHERE canonical.height >= ?1
                      AND (header.hash IS NULL OR header.height != canonical.height)
                )
                "
            ),
            params![first_height],
            |row| row.get(0),
        )
        .map_err(|error| {
            ChainError::Storage(format!(
                "could not validate staged canonical suffix: {error}"
            ))
        })?;
    if invalid_canonical_header {
        return Err(ChainError::Storage(
            "snapshot contains an invalid canonical suffix".to_owned(),
        ));
    }

    let mut previous_hash = if first_height == 0 {
        None
    } else {
        Some(
            read_canonical_hash(transaction, staged_database, first_height - 1)?.ok_or_else(
                || ChainError::Storage("staged canonical ancestor is missing".to_owned()),
            )?,
        )
    };
    let mut statement = transaction
        .prepare(&format!(
            "
            SELECT canonical.height, canonical.hash, header.header
            FROM {staged_database}.hash_by_height AS canonical
            INNER JOIN {staged_database}.headers_by_hash AS header
                ON header.hash = canonical.hash
            WHERE canonical.height >= ?1
            ORDER BY canonical.height
            "
        ))
        .map_err(|error| {
            ChainError::Storage(format!(
                "could not inspect staged canonical suffix: {error}"
            ))
        })?;
    let suffix = statement
        .query_map(params![first_height], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .map_err(|error| {
            ChainError::Storage(format!("could not query staged canonical suffix: {error}"))
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            ChainError::Storage(format!("could not decode staged canonical suffix: {error}"))
        })?;
    drop(statement);
    for (height, encoded_hash, encoded_header) in suffix {
        let hash = Hash::from_slice(&encoded_hash).map_err(|error| {
            ChainError::Storage(format!("canonical suffix hash is invalid: {error}"))
        })?;
        let header = BlockHeader::parse(&encoded_header).map_err(|error| {
            ChainError::Storage(format!("canonical suffix header is invalid: {error}"))
        })?;
        if header.hash() != hash {
            return Err(ChainError::Storage(
                "canonical suffix hash does not match its header".to_owned(),
            ));
        }
        match (height, previous_hash) {
            (0, None) if header.prev_block == Hash::ZERO => {}
            (_, Some(previous_hash)) if header.prev_block == previous_hash => {}
            _ => {
                return Err(ChainError::Storage(
                    "snapshot canonical suffix is not parent-linked".to_owned(),
                ));
            }
        }
        previous_hash = Some(hash);
    }
    Ok(())
}

fn validate_staged_canonical_publication_coverage(
    transaction: &Transaction<'_>,
    staged_database: &str,
    first_height: u32,
) -> Result<(), ChainError> {
    let uncovered_or_conflicting_header: bool = transaction
        .query_row(
            &format!(
                "
                SELECT EXISTS(
                    SELECT 1
                    FROM {staged_database}.hash_by_height AS canonical
                    INNER JOIN {staged_database}.headers_by_hash AS staged
                        ON staged.hash = canonical.hash
                    LEFT JOIN main.headers_by_hash AS live
                        ON live.hash = staged.hash
                    LEFT JOIN {staged_database}.snapshot_publication_new_headers AS delta
                        ON delta.hash = staged.hash
                    WHERE canonical.height >= ?1
                      AND (
                          live.hash IS NULL
                          OR (
                              delta.hash IS NULL
                              AND (
                                  staged.height != live.height
                                  OR staged.chainwork != live.chainwork
                                  OR staged.header != live.header
                              )
                          )
                      )
                )
                "
            ),
            params![first_height],
            |row| row.get(0),
        )
        .map_err(|error| {
            ChainError::Storage(format!(
                "could not validate staged canonical publication coverage: {error}"
            ))
        })?;
    if uncovered_or_conflicting_header {
        return Err(ChainError::Storage(
            "snapshot canonical suffix is missing a journaled header or conflicts with live storage"
                .to_owned(),
        ));
    }
    Ok(())
}

fn read_canonical_hash(
    transaction: &Transaction<'_>,
    schema: &str,
    height: u32,
) -> Result<Option<Hash>, ChainError> {
    let encoded: Option<Vec<u8>> = transaction
        .query_row(
            &format!(
                "
                SELECT hash
                FROM {schema}.hash_by_height
                WHERE height = ?1
                "
            ),
            params![height],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| {
            ChainError::Storage(format!("could not read {schema} canonical hash: {error}"))
        })?;
    encoded
        .map(|encoded| {
            Hash::from_slice(&encoded).map_err(|error| {
                ChainError::Storage(format!("{schema} canonical hash is invalid: {error}"))
            })
        })
        .transpose()
}

fn read_best_hash_in_schema(
    transaction: &Transaction<'_>,
    schema: &str,
) -> Result<Option<Hash>, ChainError> {
    let encoded: Option<Vec<u8>> = transaction
        .query_row(
            &format!(
                "
                SELECT value
                FROM {schema}.chain_state
                WHERE key = 'best_hash'
                "
            ),
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| {
            ChainError::Storage(format!("could not read {schema} best hash: {error}"))
        })?;
    encoded
        .map(|encoded| {
            Hash::from_slice(&encoded).map_err(|error| {
                ChainError::Storage(format!("{schema} best hash is invalid: {error}"))
            })
        })
        .transpose()
}

fn read_sync_generation_in_schema(
    transaction: &Transaction<'_>,
    schema: &str,
) -> Result<u64, ChainError> {
    let encoded: Option<Vec<u8>> = transaction
        .query_row(
            &format!(
                "
                SELECT value
                FROM {schema}.chain_state
                WHERE key = 'sync_generation'
                "
            ),
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| {
            ChainError::Storage(format!("could not read {schema} sync generation: {error}"))
        })?;
    let Some(encoded) = encoded else {
        return Ok(0);
    };
    let encoded: [u8; 8] = encoded.try_into().map_err(|_| {
        ChainError::Storage(format!("{schema} sync generation has an invalid length"))
    })?;
    Ok(u64::from_le_bytes(encoded))
}

fn replace_chain_state_from_snapshot(
    transaction: &Transaction<'_>,
    staged_database: &str,
) -> Result<(), ChainError> {
    transaction
        .execute(
            "
            DELETE FROM main.chain_state
            WHERE key IN ('best_hash', 'sync_generation')
            ",
            [],
        )
        .map_err(|error| ChainError::Storage(format!("could not replace chain state: {error}")))?;
    transaction
        .execute(
            &format!(
                "
                INSERT INTO main.chain_state(key, value)
                SELECT key, value
                FROM {staged_database}.chain_state
                WHERE key IN ('best_hash', 'sync_generation')
                "
            ),
            [],
        )
        .map_err(|error| ChainError::Storage(format!("could not publish chain state: {error}")))?;
    Ok(())
}

fn publish_snapshot_full(
    transaction: &Transaction<'_>,
    staged_database: &str,
) -> Result<(), ChainError> {
    let conflicting_header: bool = transaction
        .query_row(
            &format!(
                "
                SELECT EXISTS(
                    SELECT 1
                    FROM main.headers_by_hash AS live
                    INNER JOIN {staged_database}.headers_by_hash AS staged
                        ON staged.hash = live.hash
                    WHERE staged.height != live.height
                       OR staged.chainwork != live.chainwork
                       OR staged.header != live.header
                )
                "
            ),
            [],
            |row| row.get(0),
        )
        .map_err(|error| {
            ChainError::Storage(format!("could not validate staged headers: {error}"))
        })?;
    if conflicting_header {
        return Err(ChainError::Storage(
            "snapshot contains a header that conflicts with live storage".to_owned(),
        ));
    }

    let invalid_canonical_header: bool = transaction
        .query_row(
            &format!(
                "
                SELECT EXISTS(
                    SELECT 1
                    FROM {staged_database}.hash_by_height AS canonical
                    LEFT JOIN {staged_database}.headers_by_hash AS header
                        ON header.hash = canonical.hash
                    WHERE header.hash IS NULL
                       OR header.height != canonical.height
                )
                "
            ),
            [],
            |row| row.get(0),
        )
        .map_err(|error| {
            ChainError::Storage(format!(
                "could not validate staged canonical chain: {error}"
            ))
        })?;
    if invalid_canonical_header {
        return Err(ChainError::Storage(
            "snapshot contains an invalid canonical height index".to_owned(),
        ));
    }

    transaction
        .execute(
            &format!(
                "
                INSERT OR IGNORE INTO main.headers_by_hash(
                    hash,
                    height,
                    chainwork,
                    header
                )
                SELECT hash, height, chainwork, header
                FROM {staged_database}.headers_by_hash
                "
            ),
            [],
        )
        .map_err(|error| {
            ChainError::Storage(format!("could not publish staged headers: {error}"))
        })?;
    let first_divergent_height: Option<u32> = transaction
        .query_row(
            &format!(
                "
                SELECT MIN(height)
                FROM (
                    SELECT live.height AS height
                    FROM main.hash_by_height AS live
                    LEFT JOIN {staged_database}.hash_by_height AS staged
                        ON staged.height = live.height
                    WHERE staged.hash IS NULL OR staged.hash != live.hash

                    UNION ALL

                    SELECT staged.height AS height
                    FROM {staged_database}.hash_by_height AS staged
                    LEFT JOIN main.hash_by_height AS live
                        ON live.height = staged.height
                    WHERE live.hash IS NULL OR live.hash != staged.hash
                )
                "
            ),
            [],
            |row| row.get(0),
        )
        .map_err(|error| {
            ChainError::Storage(format!("could not locate canonical divergence: {error}"))
        })?;
    if let Some(first_divergent_height) = first_divergent_height {
        transaction
            .execute(
                "DELETE FROM main.hash_by_height WHERE height >= ?1",
                params![first_divergent_height],
            )
            .map_err(|error| {
                ChainError::Storage(format!("could not replace canonical suffix: {error}"))
            })?;
        transaction
            .execute(
                &format!(
                    "
                    INSERT INTO main.hash_by_height(height, hash)
                    SELECT height, hash
                    FROM {staged_database}.hash_by_height
                    WHERE height >= ?1
                    ORDER BY height
                    "
                ),
                params![first_divergent_height],
            )
            .map_err(|error| {
                ChainError::Storage(format!("could not publish canonical suffix: {error}"))
            })?;
    }
    replace_chain_state_from_snapshot(transaction, staged_database)
}

fn sqlite_path_text<'a>(path: &'a Path, role: &str) -> Result<&'a str, ChainError> {
    if path.as_os_str().is_empty() {
        return Err(ChainError::Storage(format!("{role} path is empty")));
    }
    path.to_str()
        .ok_or_else(|| ChainError::Storage(format!("{role} path is not valid UTF-8")))
}

fn read_sync_generation(connection: &Connection) -> Result<u64, ChainError> {
    let encoded: Option<Vec<u8>> = connection
        .query_row(
            "SELECT value FROM chain_state WHERE key = 'sync_generation'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| ChainError::Storage(format!("could not read sync generation: {error}")))?;
    let Some(encoded) = encoded else {
        return Ok(0);
    };
    let encoded: [u8; 8] = encoded.try_into().map_err(|_| {
        ChainError::Storage("stored sync generation has an invalid length".to_owned())
    })?;
    Ok(u64::from_le_bytes(encoded))
}

fn read_best_hash(connection: &Connection) -> Result<Option<Hash>, ChainError> {
    let encoded: Option<Vec<u8>> = connection
        .query_row(
            "SELECT value FROM chain_state WHERE key = 'best_hash'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| ChainError::Storage(format!("could not read best hash: {error}")))?;
    encoded
        .map(|encoded| {
            Hash::from_slice(&encoded).map_err(|error| {
                ChainError::Storage(format!("stored best hash is invalid: {error}"))
            })
        })
        .transpose()
}

impl HeaderStore for SqliteHeaderStore {
    fn get_header(&self, hash: Hash) -> Option<StoredHeader> {
        self.connection
            .query_row(
                "SELECT height, chainwork, header FROM headers_by_hash WHERE hash = ?1",
                params![hash.as_bytes().as_slice()],
                |row| {
                    let height: u32 = row.get(0)?;
                    let chainwork_hex: String = row.get(1)?;
                    let header_bytes: Vec<u8> = row.get(2)?;
                    let header = BlockHeader::parse(&header_bytes).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            2,
                            rusqlite::types::Type::Blob,
                            Box::new(error),
                        )
                    })?;
                    let chainwork = Chainwork::from_hex(&chainwork_hex).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;

                    Ok(StoredHeader {
                        hash,
                        header,
                        height: Height(height),
                        chainwork,
                    })
                },
            )
            .optional()
            .ok()
            .flatten()
    }

    fn put_header(&mut self, header: StoredHeader) -> Result<(), ChainError> {
        let inserted = self
            .connection
            .execute(
                "
                INSERT OR IGNORE INTO headers_by_hash(hash, height, chainwork, header)
                VALUES (?1, ?2, ?3, ?4)
                ",
                params![
                    header.hash.as_bytes().as_slice(),
                    header.height.0,
                    header.chainwork.to_hex(),
                    header.header.serialize().as_slice(),
                ],
            )
            .map_err(|error| ChainError::Storage(error.to_string()))?;

        if inserted == 0 {
            return Err(ChainError::DuplicateHeader);
        }

        Ok(())
    }

    fn put_headers(&mut self, headers: &[StoredHeader]) -> Result<(), ChainError> {
        if headers.is_empty() {
            return Ok(());
        }

        let transaction = self
            .connection
            .transaction()
            .map_err(|error| ChainError::Storage(error.to_string()))?;
        for header in headers {
            let inserted = transaction
                .execute(
                    "
                    INSERT OR IGNORE INTO headers_by_hash(hash, height, chainwork, header)
                    VALUES (?1, ?2, ?3, ?4)
                    ",
                    params![
                        header.hash.as_bytes().as_slice(),
                        header.height.0,
                        header.chainwork.to_hex(),
                        header.header.serialize().as_slice(),
                    ],
                )
                .map_err(|error| ChainError::Storage(error.to_string()))?;

            if inserted == 0 {
                return Err(ChainError::DuplicateHeader);
            }
        }
        transaction
            .commit()
            .map_err(|error| ChainError::Storage(error.to_string()))?;

        Ok(())
    }

    fn best_hash(&self) -> Option<Hash> {
        self.connection
            .query_row(
                "SELECT value FROM chain_state WHERE key = 'best_hash'",
                [],
                |row| {
                    let bytes: Vec<u8> = row.get(0)?;
                    Hash::from_slice(&bytes).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Blob,
                            Box::new(error),
                        )
                    })
                },
            )
            .optional()
            .ok()
            .flatten()
    }

    fn canonical_hash(&self, height: Height) -> Option<Hash> {
        self.connection
            .query_row(
                "SELECT hash FROM hash_by_height WHERE height = ?1",
                params![height.0],
                |row| {
                    let bytes: Vec<u8> = row.get(0)?;
                    Hash::from_slice(&bytes).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Blob,
                            Box::new(error),
                        )
                    })
                },
            )
            .optional()
            .ok()
            .flatten()
    }

    fn promote_canonical_tip(&mut self, header: &StoredHeader) -> Result<(), ChainError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(|error| ChainError::Storage(error.to_string()))?;

        transaction
            .execute(
                "
                INSERT INTO hash_by_height(height, hash)
                VALUES (?1, ?2)
                ON CONFLICT(height) DO UPDATE SET hash = excluded.hash
                ",
                params![header.height.0, header.hash.as_bytes().as_slice()],
            )
            .map_err(|error| ChainError::Storage(error.to_string()))?;
        transaction
            .execute(
                "
                INSERT INTO chain_state(key, value)
                VALUES ('best_hash', ?1)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                ",
                params![header.hash.as_bytes().as_slice()],
            )
            .map_err(|error| ChainError::Storage(error.to_string()))?;
        transaction
            .commit()
            .map_err(|error| ChainError::Storage(error.to_string()))?;

        Ok(())
    }

    fn promote_canonical_tips(&mut self, headers: &[StoredHeader]) -> Result<(), ChainError> {
        let Some(tip) = headers.last() else {
            return Ok(());
        };
        let transaction = self
            .connection
            .transaction()
            .map_err(|error| ChainError::Storage(error.to_string()))?;

        for header in headers {
            transaction
                .execute(
                    "
                    INSERT INTO hash_by_height(height, hash)
                    VALUES (?1, ?2)
                    ON CONFLICT(height) DO UPDATE SET hash = excluded.hash
                    ",
                    params![header.height.0, header.hash.as_bytes().as_slice()],
                )
                .map_err(|error| ChainError::Storage(error.to_string()))?;
        }
        transaction
            .execute(
                "
                INSERT INTO chain_state(key, value)
                VALUES ('best_hash', ?1)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                ",
                params![tip.hash.as_bytes().as_slice()],
            )
            .map_err(|error| ChainError::Storage(error.to_string()))?;
        transaction
            .commit()
            .map_err(|error| ChainError::Storage(error.to_string()))?;

        Ok(())
    }

    fn replace_canonical_chain(&mut self, headers: &[StoredHeader]) -> Result<(), ChainError> {
        let Some(tip) = headers.last() else {
            return Err(ChainError::MissingBestHeader);
        };
        let transaction = self
            .connection
            .transaction()
            .map_err(|error| ChainError::Storage(error.to_string()))?;

        transaction
            .execute("DELETE FROM hash_by_height", [])
            .map_err(|error| ChainError::Storage(error.to_string()))?;
        for header in headers {
            transaction
                .execute(
                    "
                    INSERT INTO hash_by_height(height, hash)
                    VALUES (?1, ?2)
                    ",
                    params![header.height.0, header.hash.as_bytes().as_slice()],
                )
                .map_err(|error| ChainError::Storage(error.to_string()))?;
        }
        transaction
            .execute(
                "
                INSERT INTO chain_state(key, value)
                VALUES ('best_hash', ?1)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                ",
                params![tip.hash.as_bytes().as_slice()],
            )
            .map_err(|error| ChainError::Storage(error.to_string()))?;
        transaction
            .commit()
            .map_err(|error| ChainError::Storage(error.to_string()))?;

        Ok(())
    }
}

impl<S: HeaderStore> HeaderChain<S> {
    pub fn new(store: S) -> Self {
        Self::with_difficulty_policy(store, DifficultyPolicy::Mainnet)
    }

    pub fn with_difficulty_policy(store: S, difficulty_policy: DifficultyPolicy) -> Self {
        Self {
            store,
            difficulty_policy,
        }
    }

    pub fn insert_genesis(&mut self, header: BlockHeader) -> Result<StoredHeader, ChainError> {
        self.validate_genesis(&header)?;
        let hash = header.hash();
        let stored = StoredHeader {
            hash,
            chainwork: Chainwork::from_bits(header.bits)?,
            header,
            height: Height(0),
        };

        self.store.put_header(stored.clone())?;
        self.promote_best_hash(hash)?;
        Ok(stored)
    }

    pub fn insert_header(&mut self, header: BlockHeader) -> Result<StoredHeader, ChainError> {
        let parent = self
            .store
            .get_header(header.prev_block)
            .ok_or(ChainError::UnknownParent)?;
        let hash = header.hash();
        let height = Height(
            parent
                .height
                .0
                .checked_add(1)
                .ok_or(ChainError::InvalidDifficultyWindow)?,
        );
        self.validate_difficulty_bits(&header, &parent)?;
        if !verify_pow(hash, header.bits)? {
            return Err(ChainError::InvalidProofOfWork);
        }
        self.validate_checkpoint(height, hash)?;
        let chainwork = parent
            .chainwork
            .checked_add(&Chainwork::from_bits(header.bits)?);
        let stored = StoredHeader {
            hash,
            header,
            height,
            chainwork,
        };

        self.store.put_header(stored.clone())?;

        let best = self.best_header()?;
        let extends_best = best
            .as_ref()
            .is_some_and(|best| stored.header.prev_block == best.hash);
        let should_promote = match best {
            Some(best) => stored.chainwork > best.chainwork,
            None => true,
        };

        if should_promote {
            if extends_best {
                self.store.promote_canonical_tip(&stored)?;
            } else {
                self.promote_best_hash(hash)?;
            }
        }

        Ok(stored)
    }

    pub fn insert_headers<I>(&mut self, headers: I) -> Result<Vec<StoredHeader>, ChainError>
    where
        I: IntoIterator<Item = BlockHeader>,
    {
        let mut accepted = Vec::new();
        let mut pending = HashMap::new();
        let mut seen = HashSet::new();
        let mut chainwork_by_bits = HashMap::new();

        for header in headers {
            let hash = header.hash();
            if !seen.insert(hash) || self.store.get_header(hash).is_some() {
                continue;
            }
            let parent = pending
                .get(&header.prev_block)
                .cloned()
                .or_else(|| self.store.get_header(header.prev_block))
                .ok_or(ChainError::UnknownParent)?;
            self.validate_difficulty_bits_with_pending(&header, &parent, &pending)?;
            if !verify_pow(hash, header.bits)? {
                return Err(ChainError::InvalidProofOfWork);
            }
            let height = Height(
                parent
                    .height
                    .0
                    .checked_add(1)
                    .ok_or(ChainError::InvalidDifficultyWindow)?,
            );
            self.validate_checkpoint(height, hash)?;
            let header_work = match chainwork_by_bits.get(&header.bits) {
                Some(work) => work,
                None => {
                    chainwork_by_bits.insert(header.bits, Chainwork::from_bits(header.bits)?);
                    chainwork_by_bits
                        .get(&header.bits)
                        .ok_or(ChainError::InvalidDifficultyWindow)?
                }
            };
            let chainwork = parent.chainwork.checked_add(header_work);
            let stored = StoredHeader {
                hash,
                header,
                height,
                chainwork,
            };
            pending.insert(hash, stored.clone());
            accepted.push(stored);
        }

        if accepted.is_empty() {
            return Ok(accepted);
        }

        let best = self.best_header()?;
        let (best_index, best_candidate) = accepted
            .iter()
            .enumerate()
            .max_by(|(_, left), (_, right)| left.chainwork.cmp(&right.chainwork))
            .map(|(index, header)| (index, header.clone()))
            .ok_or(ChainError::MissingBestHeader)?;
        let should_promote = match &best {
            Some(best) => best_candidate.chainwork > best.chainwork,
            None => true,
        };
        let extends_best = best.as_ref().is_some_and(|best| {
            accepted
                .first()
                .is_some_and(|header| header.header.prev_block == best.hash)
                && accepted[..=best_index]
                    .windows(2)
                    .all(|window| window[1].header.prev_block == window[0].hash)
        });

        self.store.put_headers(&accepted)?;

        if should_promote {
            if extends_best {
                self.store
                    .promote_canonical_tips(&accepted[..=best_index])?;
            } else {
                self.promote_best_hash(best_candidate.hash)?;
            }
        }

        Ok(accepted)
    }

    pub fn best_header(&self) -> Result<Option<StoredHeader>, ChainError> {
        match self.store.best_hash() {
            Some(hash) => self
                .store
                .get_header(hash)
                .map(Some)
                .ok_or(ChainError::MissingBestHeader),
            None => Ok(None),
        }
    }

    pub fn get_header(&self, hash: Hash) -> Option<StoredHeader> {
        self.store.get_header(hash)
    }

    pub fn canonical_hash(&self, height: Height) -> Option<Hash> {
        self.store.canonical_hash(height)
    }

    pub fn canonical_header(&self, height: Height) -> Option<StoredHeader> {
        self.canonical_hash(height)
            .and_then(|hash| self.store.get_header(hash))
    }

    pub fn into_store(self) -> S {
        self.store
    }

    fn promote_best_hash(&mut self, hash: Hash) -> Result<(), ChainError> {
        let headers = self.canonical_chain_to(hash)?;
        self.store.replace_canonical_chain(&headers)
    }

    fn validate_genesis(&self, header: &BlockHeader) -> Result<(), ChainError> {
        if self.difficulty_policy == DifficultyPolicy::Mainnet
            && header != &BlockHeader::mainnet_genesis()
        {
            return Err(ChainError::InvalidGenesisHeader);
        }

        Ok(())
    }

    fn validate_checkpoint(&self, height: Height, hash: Hash) -> Result<(), ChainError> {
        if self.difficulty_policy != DifficultyPolicy::Mainnet {
            return Ok(());
        }

        let Some(expected) = mainnet_checkpoint_hash(height) else {
            return Ok(());
        };

        if hash != expected {
            return Err(ChainError::InvalidCheckpoint {
                height: height.0,
                actual: hash,
                expected,
            });
        }

        Ok(())
    }

    fn validate_difficulty_bits(
        &self,
        header: &BlockHeader,
        parent: &StoredHeader,
    ) -> Result<(), ChainError> {
        self.validate_difficulty_bits_with_pending(header, parent, &HashMap::new())
    }

    fn validate_difficulty_bits_with_pending(
        &self,
        header: &BlockHeader,
        parent: &StoredHeader,
        pending: &HashMap<Hash, StoredHeader>,
    ) -> Result<(), ChainError> {
        let DifficultyPolicy::Mainnet = self.difficulty_policy else {
            return Ok(());
        };

        let expected = self.expected_mainnet_bits_with_pending(parent, pending)?;
        if header.bits != expected {
            return Err(ChainError::InvalidDifficultyBits {
                actual: header.bits,
                expected,
            });
        }

        Ok(())
    }

    #[cfg(test)]
    fn expected_mainnet_bits(&self, parent: &StoredHeader) -> Result<u32, ChainError> {
        self.expected_mainnet_bits_with_pending(parent, &HashMap::new())
    }

    fn expected_mainnet_bits_with_pending(
        &self,
        parent: &StoredHeader,
        pending: &HashMap<Hash, StoredHeader>,
    ) -> Result<u32, ChainError> {
        if parent.height.0 < MAINNET_BLOCKS_PER_DAY + 2 {
            return Ok(MAINNET_POW_BITS);
        }

        let last = self.suitable_block_with_pending(parent, pending)?;
        let ancestor = self.ancestor_with_pending(
            parent,
            Height(parent.height.0 - MAINNET_BLOCKS_PER_DAY),
            pending,
        )?;
        let first = self.suitable_block_with_pending(&ancestor, pending)?;

        self.retarget_bits(&first, &last)
    }

    fn retarget_bits(&self, first: &StoredHeader, last: &StoredHeader) -> Result<u32, ChainError> {
        if last.height.0 <= first.height.0 {
            return Err(ChainError::InvalidDifficultyWindow);
        }

        let mut actual_timespan = last.header.time.saturating_sub(first.header.time);
        actual_timespan =
            actual_timespan.clamp(MAINNET_MIN_ACTUAL_TIMESPAN, MAINNET_MAX_ACTUAL_TIMESPAN);

        let work = last
            .chainwork
            .checked_sub(&first.chainwork)
            .ok_or(ChainError::InvalidDifficultyWindow)?
            .mul_u64(MAINNET_TARGET_SPACING)
            .div_u64(actual_timespan)
            .ok_or(ChainError::InvalidDifficultyWindow)?;

        if work.is_zero() {
            return Ok(MAINNET_POW_BITS);
        }

        let target = target_for_work(&work)?;
        if target > Target::from_compact(MAINNET_POW_BITS)? {
            return Ok(MAINNET_POW_BITS);
        }

        Ok(target.to_compact())
    }

    fn suitable_block_with_pending(
        &self,
        header: &StoredHeader,
        pending: &HashMap<Hash, StoredHeader>,
    ) -> Result<StoredHeader, ChainError> {
        let z = header.clone();
        let y = self.previous_with_pending(&z, pending)?;
        let x = self.previous_with_pending(&y, pending)?;
        let mut blocks = [x, y, z];
        blocks.sort_by_key(|block| block.header.time);

        Ok(blocks[1].clone())
    }

    fn ancestor_with_pending(
        &self,
        header: &StoredHeader,
        height: Height,
        pending: &HashMap<Hash, StoredHeader>,
    ) -> Result<StoredHeader, ChainError> {
        if height.0 > header.height.0 {
            return Err(ChainError::InvalidDifficultyWindow);
        }

        let mut current = header.clone();
        while current.height.0 > height.0 {
            current = self.previous_with_pending(&current, pending)?;
        }

        Ok(current)
    }

    fn previous_with_pending(
        &self,
        header: &StoredHeader,
        pending: &HashMap<Hash, StoredHeader>,
    ) -> Result<StoredHeader, ChainError> {
        let previous = pending
            .get(&header.header.prev_block)
            .cloned()
            .or_else(|| self.store.get_header(header.header.prev_block))
            .ok_or(ChainError::UnknownParent)?;
        if previous.height.0.checked_add(1) != Some(header.height.0) {
            return Err(ChainError::InvalidDifficultyWindow);
        }
        Ok(previous)
    }

    fn canonical_chain_to(&self, hash: Hash) -> Result<Vec<StoredHeader>, ChainError> {
        let mut current = self
            .store
            .get_header(hash)
            .ok_or(ChainError::MissingBestHeader)?;
        let mut headers = vec![current.clone()];

        while current.height.0 > 0 {
            let previous = self
                .store
                .get_header(current.header.prev_block)
                .ok_or(ChainError::UnknownParent)?;
            if previous.height.0.checked_add(1) != Some(current.height.0) {
                return Err(ChainError::InvalidDifficultyWindow);
            }
            current = previous;
            headers.push(current.clone());
        }

        headers.reverse();
        Ok(headers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_genesis_as_best_tip() {
        let mut chain = HeaderChain::new(MemoryHeaderStore::default());
        let genesis = chain
            .insert_genesis(BlockHeader::mainnet_genesis())
            .unwrap();

        assert_eq!(chain.best_header().unwrap().unwrap(), genesis);
    }

    #[test]
    fn rejects_unknown_parent() {
        let mut chain = HeaderChain::new(MemoryHeaderStore::default());
        let header = BlockHeader::mainnet_genesis();

        assert_eq!(
            chain.insert_header(header).unwrap_err(),
            ChainError::UnknownParent,
        );
    }

    #[test]
    fn rejects_height_overflow_from_corrupt_store() {
        let mut store = MemoryHeaderStore::default();
        let parent_header = BlockHeader::mainnet_genesis();
        let parent = StoredHeader {
            hash: parent_header.hash(),
            header: parent_header,
            height: Height(u32::MAX),
            chainwork: Chainwork::zero(),
        };
        store.put_header(parent.clone()).unwrap();
        store.promote_canonical_tip(&parent).unwrap();
        let mut child = BlockHeader::mainnet_genesis();
        child.prev_block = parent.hash;
        child.bits = 0x207f_ffff;
        let mut chain = permissive_chain(store);

        assert_eq!(
            chain.insert_header(child).unwrap_err(),
            ChainError::InvalidDifficultyWindow
        );
    }

    #[test]
    fn sqlite_store_survives_reopen_from_connection() {
        let store = SqliteHeaderStore::in_memory().unwrap();
        let mut chain = HeaderChain::new(store);
        let genesis = chain
            .insert_genesis(BlockHeader::mainnet_genesis())
            .unwrap();

        assert_eq!(chain.best_header().unwrap().unwrap(), genesis);
        assert_eq!(chain.canonical_hash(Height(0)), Some(genesis.hash));
    }

    #[test]
    fn sqlite_sync_generation_defaults_to_zero_and_round_trips() {
        let mut store = SqliteHeaderStore::in_memory().unwrap();

        assert_eq!(store.sync_generation().unwrap(), 0);
        store.set_sync_generation(42).unwrap();
        assert_eq!(store.sync_generation().unwrap(), 42);
        store.set_sync_generation(u64::MAX).unwrap();
        assert_eq!(store.sync_generation().unwrap(), u64::MAX);
    }

    #[test]
    fn rejects_header_that_fails_pow() {
        let mut chain = permissive_chain(MemoryHeaderStore::default());
        let genesis = chain
            .insert_genesis(BlockHeader::mainnet_genesis())
            .unwrap();
        let mut child = BlockHeader::mainnet_genesis();
        child.prev_block = genesis.hash;
        child.bits = 0x01010000;

        assert_eq!(
            chain.insert_header(child).unwrap_err(),
            ChainError::InvalidProofOfWork,
        );
    }

    #[test]
    fn rejects_non_mainnet_genesis_by_default() {
        let mut chain = HeaderChain::new(MemoryHeaderStore::default());
        let mut genesis = BlockHeader::mainnet_genesis();
        genesis.time += 1;

        assert_eq!(
            chain.insert_genesis(genesis).unwrap_err(),
            ChainError::InvalidGenesisHeader,
        );
    }

    #[test]
    fn rejects_unexpected_mainnet_difficulty_bits() {
        let mut chain = HeaderChain::new(MemoryHeaderStore::default());
        let genesis = chain
            .insert_genesis(BlockHeader::mainnet_genesis())
            .unwrap();
        let child = low_difficulty_child(&genesis, 1);

        assert_eq!(
            chain.insert_header(child).unwrap_err(),
            ChainError::InvalidDifficultyBits {
                actual: 0x207f_ffff,
                expected: MAINNET_POW_BITS,
            },
        );
    }

    #[test]
    fn mainnet_checkpoint_hashes_include_sync_anchors() {
        assert_eq!(
            mainnet_checkpoint_hash(Height(50_000)).unwrap().to_string(),
            "00000000000000020c7447e7139feeb90549bfc77a7f18d4ff28f327c04f8d6e",
        );
        assert_eq!(
            mainnet_checkpoint_hash(Height(258_026))
                .unwrap()
                .to_string(),
            "0000000000000004963d20732c58e5a91cb7e1b61ec6709d031f1a5ca8c55b95",
        );
        assert_eq!(
            mainnet_sync_checkpoints()
                .into_iter()
                .map(|checkpoint| checkpoint.height.0)
                .collect::<Vec<_>>(),
            vec![50_000, 100_000, 160_000, 200_000, 225_000, 258_026],
        );
    }

    #[test]
    fn mainnet_checkpoint_mismatch_is_rejected() {
        let chain = HeaderChain::new(MemoryHeaderStore::default());
        let expected = mainnet_checkpoint_hash(Height(50_000)).unwrap();

        assert_eq!(
            chain
                .validate_checkpoint(Height(50_000), Hash::ZERO)
                .unwrap_err(),
            ChainError::InvalidCheckpoint {
                height: 50_000,
                actual: Hash::ZERO,
                expected,
            },
        );
    }

    #[test]
    fn mainnet_retarget_matches_hsd_after_initial_window() {
        let chain = seeded_mainnet_chain_with_spacing(MAINNET_TARGET_SPACING / 4);
        let parent = chain.best_header().unwrap().unwrap();

        assert_eq!(parent.height, Height(MAINNET_BLOCKS_PER_DAY + 2));
        assert_eq!(chain.expected_mainnet_bits(&parent).unwrap(), 0x1b3fffc0);
    }

    #[test]
    fn canonical_height_index_tracks_reorg_to_more_work_branch() {
        let mut chain = permissive_chain(MemoryHeaderStore::default());
        let genesis = chain
            .insert_genesis(BlockHeader::mainnet_genesis())
            .unwrap();
        let a1 = chain
            .insert_header(low_difficulty_child(&genesis, 1))
            .unwrap();
        let a2 = chain.insert_header(low_difficulty_child(&a1, 2)).unwrap();
        let b1 = chain
            .insert_header(low_difficulty_child(&genesis, 3))
            .unwrap();
        let b2 = chain.insert_header(low_difficulty_child(&b1, 4)).unwrap();

        assert_eq!(chain.best_header().unwrap().unwrap(), a2);
        assert_eq!(chain.canonical_hash(Height(1)), Some(a1.hash));
        assert_eq!(chain.canonical_hash(Height(2)), Some(a2.hash));

        let b3 = chain.insert_header(low_difficulty_child(&b2, 5)).unwrap();

        assert_eq!(chain.best_header().unwrap().unwrap(), b3);
        assert_eq!(chain.canonical_hash(Height(0)), Some(genesis.hash));
        assert_eq!(chain.canonical_hash(Height(1)), Some(b1.hash));
        assert_eq!(chain.canonical_hash(Height(2)), Some(b2.hash));
        assert_eq!(chain.canonical_hash(Height(3)), Some(b3.hash));
        assert_eq!(chain.canonical_hash(Height(4)), None);
        assert_eq!(chain.canonical_header(Height(2)).unwrap(), b2);
    }

    #[test]
    fn sqlite_canonical_height_index_survives_reopen() {
        let path = temp_db_path("canonical-height");
        let genesis;
        let child;
        {
            let store = SqliteHeaderStore::open(&path).unwrap();
            let mut chain = permissive_chain(store);
            genesis = chain
                .insert_genesis(BlockHeader::mainnet_genesis())
                .unwrap();
            child = chain
                .insert_header(low_difficulty_child(&genesis, 9))
                .unwrap();
            chain.into_store().flush().unwrap();
        }

        {
            let store = SqliteHeaderStore::open(&path).unwrap();
            let chain = permissive_chain(store);

            assert_eq!(chain.best_header().unwrap().unwrap(), child);
            assert_eq!(chain.canonical_hash(Height(0)), Some(genesis.hash));
            assert_eq!(chain.canonical_hash(Height(1)), Some(child.hash));
            assert_eq!(chain.canonical_header(Height(1)).unwrap(), child);
            chain.into_store().flush().unwrap();
        }

        cleanup_db_path(&path);
    }

    #[test]
    fn sqlite_batch_header_insert_survives_reopen() {
        let path = temp_db_path("batch-headers");
        let genesis;
        let child;
        let grandchild;
        {
            let store = SqliteHeaderStore::open(&path).unwrap();
            let mut chain = permissive_chain(store);
            genesis = chain
                .insert_genesis(BlockHeader::mainnet_genesis())
                .unwrap();
            let child_header = low_difficulty_child(&genesis, 12);
            let child_stub = StoredHeader {
                hash: child_header.hash(),
                header: child_header.clone(),
                height: Height(1),
                chainwork: Chainwork::zero(),
            };
            let grandchild_header = low_difficulty_child(&child_stub, 13);
            let accepted = chain
                .insert_headers([child_header, grandchild_header])
                .unwrap();
            child = accepted[0].clone();
            grandchild = accepted[1].clone();
            chain.into_store().flush().unwrap();
        }

        {
            let store = SqliteHeaderStore::open(&path).unwrap();
            let chain = permissive_chain(store);

            assert_eq!(chain.best_header().unwrap().unwrap(), grandchild);
            assert_eq!(chain.canonical_hash(Height(0)), Some(genesis.hash));
            assert_eq!(chain.canonical_hash(Height(1)), Some(child.hash));
            assert_eq!(chain.canonical_hash(Height(2)), Some(grandchild.hash));
            chain.into_store().flush().unwrap();
        }

        cleanup_db_path(&path);
    }

    #[test]
    fn sqlite_snapshot_is_isolated_from_later_live_writes() {
        let live_path = temp_db_path("snapshot-isolation-live");
        let staged_path = temp_db_path("snapshot-isolation-staged");

        let live_store = SqliteHeaderStore::open(&live_path).unwrap();
        let mut live_chain = permissive_chain(live_store);
        let genesis = live_chain
            .insert_genesis(BlockHeader::mainnet_genesis())
            .unwrap();
        let snapshotted_tip = live_chain
            .insert_header(low_difficulty_child(&genesis, 19))
            .unwrap();
        live_chain.into_store().snapshot_to(&staged_path).unwrap();

        let live_store = SqliteHeaderStore::open(&live_path).unwrap();
        let mut live_chain = permissive_chain(live_store);
        let later_live_tip = live_chain
            .insert_header(low_difficulty_child(&snapshotted_tip, 20))
            .unwrap();
        live_chain.into_store().flush().unwrap();

        let staged_store = SqliteHeaderStore::open(&staged_path).unwrap();
        assert_eq!(staged_store.best_hash(), Some(snapshotted_tip.hash));
        assert_eq!(staged_store.canonical_hash(Height(2)), None);
        assert_eq!(staged_store.get_header(later_live_tip.hash), None);
        staged_store.flush().unwrap();

        cleanup_db_path(&staged_path);
        cleanup_db_path(&live_path);
    }

    #[test]
    fn sqlite_conditional_snapshot_publication_rejects_changed_live_state() {
        let live_path = temp_db_path("snapshot-cas-live");
        let staged_path = temp_db_path("snapshot-cas-staged");

        let live_store = SqliteHeaderStore::open(&live_path).unwrap();
        let mut live_chain = permissive_chain(live_store);
        let genesis = live_chain
            .insert_genesis(BlockHeader::mainnet_genesis())
            .unwrap();
        let live_tip = live_chain
            .insert_header(low_difficulty_child(&genesis, 23))
            .unwrap();
        let mut live_store = live_chain.into_store();
        live_store.set_sync_generation(11).unwrap();
        live_store.snapshot_to(&staged_path).unwrap();

        let staged_tip = {
            let mut staged_store = SqliteHeaderStore::open(&staged_path).unwrap();
            staged_store
                .begin_snapshot_publication_delta(11, Some(live_tip.hash))
                .unwrap();
            let mut staged_chain = permissive_chain(staged_store);
            let staged_tip = staged_chain
                .insert_header(low_difficulty_child(&live_tip, 24))
                .unwrap();
            let mut staged_store = staged_chain.into_store();
            staged_store.set_sync_generation(12).unwrap();
            staged_store.flush().unwrap();
            staged_tip
        };

        live_store.set_sync_generation(13).unwrap();
        assert!(
            !live_store
                .publish_snapshot_from_if_current(&staged_path, 11, Some(live_tip.hash))
                .unwrap()
        );
        assert!(
            !live_store
                .publish_snapshot_from_if_current(&staged_path, 13, Some(genesis.hash))
                .unwrap()
        );

        assert_eq!(live_store.sync_generation().unwrap(), 13);
        assert_eq!(live_store.best_hash(), Some(live_tip.hash));
        assert_eq!(live_store.canonical_hash(Height(2)), None);
        assert_eq!(live_store.get_header(staged_tip.hash), None);

        live_store.flush().unwrap();
        cleanup_db_path(&staged_path);
        cleanup_db_path(&live_path);
    }

    #[test]
    fn sqlite_snapshot_plus_one_publication_only_inserts_new_canonical_tip() {
        let live_path = temp_db_path("snapshot-delta-live");
        let staged_path = temp_db_path("snapshot-delta-staged");

        let live_store = SqliteHeaderStore::open(&live_path).unwrap();
        let mut live_chain = permissive_chain(live_store);
        let genesis = live_chain
            .insert_genesis(BlockHeader::mainnet_genesis())
            .unwrap();
        let live_tip = live_chain
            .insert_header(low_difficulty_child(&genesis, 25))
            .unwrap();
        let mut live_store = live_chain.into_store();
        live_store.set_sync_generation(20).unwrap();
        live_store.snapshot_to(&staged_path).unwrap();

        let staged_tip = {
            let mut staged_store = SqliteHeaderStore::open(&staged_path).unwrap();
            staged_store
                .begin_snapshot_publication_delta(20, Some(live_tip.hash))
                .unwrap();
            let mut staged_chain = permissive_chain(staged_store);
            let staged_tip = staged_chain
                .insert_header(low_difficulty_child(&live_tip, 26))
                .unwrap();
            let mut staged_store = staged_chain.into_store();
            staged_store.set_sync_generation(21).unwrap();
            staged_store.flush().unwrap();
            staged_tip
        };

        live_store
            .connection
            .execute_batch(
                "
                CREATE TABLE canonical_publication_audit (
                    action TEXT NOT NULL,
                    height INTEGER NOT NULL
                );
                CREATE TABLE header_publication_audit (
                    hash BLOB NOT NULL
                );
                CREATE TRIGGER audit_canonical_delete
                AFTER DELETE ON hash_by_height
                BEGIN
                    INSERT INTO canonical_publication_audit(action, height)
                    VALUES ('delete', OLD.height);
                END;
                CREATE TRIGGER audit_canonical_insert
                AFTER INSERT ON hash_by_height
                BEGIN
                    INSERT INTO canonical_publication_audit(action, height)
                    VALUES ('insert', NEW.height);
                END;
                CREATE TRIGGER audit_header_insert
                AFTER INSERT ON headers_by_hash
                BEGIN
                    INSERT INTO header_publication_audit(hash)
                    VALUES (NEW.hash);
                END;
                ",
            )
            .unwrap();

        assert!(
            live_store
                .publish_snapshot_from_if_current(&staged_path, 20, Some(live_tip.hash))
                .unwrap()
        );

        let mut statement = live_store
            .connection
            .prepare(
                "
                SELECT action, height
                FROM canonical_publication_audit
                ORDER BY rowid
                ",
            )
            .unwrap();
        let writes = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        drop(statement);

        assert_eq!(writes, vec![("insert".to_owned(), 2)]);
        let mut statement = live_store
            .connection
            .prepare("SELECT hash FROM header_publication_audit ORDER BY rowid")
            .unwrap();
        let inserted_headers: Vec<Vec<u8>> = statement
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        drop(statement);
        assert_eq!(inserted_headers, vec![staged_tip.hash.as_bytes().to_vec()]);
        assert_eq!(live_store.best_hash(), Some(staged_tip.hash));
        assert_eq!(live_store.sync_generation().unwrap(), 21);
        assert_eq!(live_store.canonical_hash(Height(0)), Some(genesis.hash));
        assert_eq!(live_store.canonical_hash(Height(1)), Some(live_tip.hash));
        assert_eq!(live_store.canonical_hash(Height(2)), Some(staged_tip.hash));

        live_store.flush().unwrap();
        cleanup_db_path(&staged_path);
        cleanup_db_path(&live_path);
    }

    #[test]
    fn sqlite_conditional_snapshot_rejects_missing_and_mismatched_delta_markers() {
        let live_path = temp_db_path("snapshot-marker-live");
        let missing_marker_path = temp_db_path("snapshot-marker-missing");
        let mismatched_marker_path = temp_db_path("snapshot-marker-mismatch");

        let live_store = SqliteHeaderStore::open(&live_path).unwrap();
        let mut live_chain = permissive_chain(live_store);
        let genesis = live_chain
            .insert_genesis(BlockHeader::mainnet_genesis())
            .unwrap();
        let live_tip = live_chain
            .insert_header(low_difficulty_child(&genesis, 41))
            .unwrap();
        let mut live_store = live_chain.into_store();
        live_store.set_sync_generation(30).unwrap();
        live_store.snapshot_to(&missing_marker_path).unwrap();
        live_store.snapshot_to(&mismatched_marker_path).unwrap();

        let missing_marker_tip = {
            let staged_store = SqliteHeaderStore::open(&missing_marker_path).unwrap();
            let mut staged_chain = permissive_chain(staged_store);
            let staged_tip = staged_chain
                .insert_header(low_difficulty_child(&live_tip, 42))
                .unwrap();
            let mut staged_store = staged_chain.into_store();
            staged_store.set_sync_generation(31).unwrap();
            staged_store.flush().unwrap();
            staged_tip
        };
        let missing_marker_error = live_store
            .publish_snapshot_from_if_current(&missing_marker_path, 30, Some(live_tip.hash))
            .unwrap_err();
        assert!(
            missing_marker_error
                .to_string()
                .contains("missing its publication delta baseline")
        );
        assert_eq!(live_store.best_hash(), Some(live_tip.hash));
        assert_eq!(live_store.sync_generation().unwrap(), 30);
        assert_eq!(live_store.get_header(missing_marker_tip.hash), None);

        let mismatched_marker_tip = {
            let mut staged_store = SqliteHeaderStore::open(&mismatched_marker_path).unwrap();
            staged_store
                .begin_snapshot_publication_delta(30, Some(live_tip.hash))
                .unwrap();
            let mut staged_chain = permissive_chain(staged_store);
            let staged_tip = staged_chain
                .insert_header(low_difficulty_child(&live_tip, 43))
                .unwrap();
            let mut staged_store = staged_chain.into_store();
            staged_store.set_sync_generation(31).unwrap();
            staged_store
                .connection
                .execute(
                    "
                    UPDATE snapshot_publication_baseline
                    SET sync_generation = ?1
                    WHERE singleton = 1
                    ",
                    params![29_u64.to_le_bytes().as_slice()],
                )
                .unwrap();
            staged_store.flush().unwrap();
            staged_tip
        };
        let mismatched_marker_error = live_store
            .publish_snapshot_from_if_current(&mismatched_marker_path, 30, Some(live_tip.hash))
            .unwrap_err();
        assert!(
            mismatched_marker_error
                .to_string()
                .contains("baseline does not match the expected live state")
        );
        assert_eq!(live_store.best_hash(), Some(live_tip.hash));
        assert_eq!(live_store.sync_generation().unwrap(), 30);
        assert_eq!(live_store.get_header(mismatched_marker_tip.hash), None);

        live_store.flush().unwrap();
        cleanup_db_path(&mismatched_marker_path);
        cleanup_db_path(&missing_marker_path);
        cleanup_db_path(&live_path);
    }

    #[test]
    fn sqlite_conditional_snapshot_rejects_deleted_canonical_journal_entry_atomically() {
        let live_path = temp_db_path("snapshot-journal-tamper-live");
        let staged_path = temp_db_path("snapshot-journal-tamper-stage");

        let live_store = SqliteHeaderStore::open(&live_path).unwrap();
        let mut live_chain = permissive_chain(live_store);
        let genesis = live_chain
            .insert_genesis(BlockHeader::mainnet_genesis())
            .unwrap();
        let live_tip = live_chain
            .insert_header(low_difficulty_child(&genesis, 44))
            .unwrap();
        let mut live_store = live_chain.into_store();
        live_store.set_sync_generation(40).unwrap();
        live_store.snapshot_to(&staged_path).unwrap();

        let staged_tip = {
            let mut staged_store = SqliteHeaderStore::open(&staged_path).unwrap();
            staged_store
                .begin_snapshot_publication_delta(40, Some(live_tip.hash))
                .unwrap();
            let mut staged_chain = permissive_chain(staged_store);
            let staged_tip = staged_chain
                .insert_header(low_difficulty_child(&live_tip, 45))
                .unwrap();
            let mut staged_store = staged_chain.into_store();
            staged_store.set_sync_generation(41).unwrap();
            staged_store
                .connection
                .execute(
                    "
                    DELETE FROM snapshot_publication_new_headers
                    WHERE hash = ?1
                    ",
                    params![staged_tip.hash.as_bytes().as_slice()],
                )
                .unwrap();
            staged_store.flush().unwrap();
            staged_tip
        };

        let error = live_store
            .publish_snapshot_from_if_current(&staged_path, 40, Some(live_tip.hash))
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("missing a journaled header or conflicts with live storage")
        );
        assert_eq!(live_store.best_hash(), Some(live_tip.hash));
        assert_eq!(live_store.sync_generation().unwrap(), 40);
        assert_eq!(live_store.canonical_hash(Height(2)), None);
        assert_eq!(live_store.get_header(staged_tip.hash), None);

        live_store.flush().unwrap();
        cleanup_db_path(&staged_path);
        cleanup_db_path(&live_path);
    }

    #[test]
    fn sqlite_conditional_snapshot_publishes_only_a_shallow_reorg_suffix() {
        let live_path = temp_db_path("snapshot-conditional-reorg-live");
        let staged_path = temp_db_path("snapshot-conditional-reorg-stage");

        let live_store = SqliteHeaderStore::open(&live_path).unwrap();
        let mut live_chain = permissive_chain(live_store);
        let genesis = live_chain
            .insert_genesis(BlockHeader::mainnet_genesis())
            .unwrap();
        let a1 = live_chain
            .insert_header(low_difficulty_child(&genesis, 46))
            .unwrap();
        let a2 = live_chain
            .insert_header(low_difficulty_child(&a1, 47))
            .unwrap();
        let mut live_store = live_chain.into_store();
        live_store.set_sync_generation(50).unwrap();
        live_store.snapshot_to(&staged_path).unwrap();

        let (b1, b2, b3) = {
            let mut staged_store = SqliteHeaderStore::open(&staged_path).unwrap();
            staged_store
                .begin_snapshot_publication_delta(50, Some(a2.hash))
                .unwrap();
            let mut staged_chain = permissive_chain(staged_store);
            let b1 = staged_chain
                .insert_header(low_difficulty_child(&genesis, 48))
                .unwrap();
            let b2 = staged_chain
                .insert_header(low_difficulty_child(&b1, 49))
                .unwrap();
            let b3 = staged_chain
                .insert_header(low_difficulty_child(&b2, 50))
                .unwrap();
            let mut staged_store = staged_chain.into_store();
            staged_store.set_sync_generation(51).unwrap();
            staged_store.flush().unwrap();
            (b1, b2, b3)
        };

        live_store
            .connection
            .execute_batch(
                "
                CREATE TABLE conditional_reorg_audit (
                    action TEXT NOT NULL,
                    height INTEGER NOT NULL
                );
                CREATE TABLE conditional_reorg_header_audit (
                    hash BLOB NOT NULL
                );
                CREATE TRIGGER audit_conditional_reorg_delete
                AFTER DELETE ON hash_by_height
                BEGIN
                    INSERT INTO conditional_reorg_audit(action, height)
                    VALUES ('delete', OLD.height);
                END;
                CREATE TRIGGER audit_conditional_reorg_insert
                AFTER INSERT ON hash_by_height
                BEGIN
                    INSERT INTO conditional_reorg_audit(action, height)
                    VALUES ('insert', NEW.height);
                END;
                CREATE TRIGGER audit_conditional_reorg_header_insert
                AFTER INSERT ON headers_by_hash
                BEGIN
                    INSERT INTO conditional_reorg_header_audit(hash)
                    VALUES (NEW.hash);
                END;
                ",
            )
            .unwrap();

        assert!(
            live_store
                .publish_snapshot_from_if_current(&staged_path, 50, Some(a2.hash))
                .unwrap()
        );

        let mut statement = live_store
            .connection
            .prepare(
                "
                SELECT action, height
                FROM conditional_reorg_audit
                ORDER BY action, height
                ",
            )
            .unwrap();
        let canonical_writes = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        drop(statement);
        assert_eq!(
            canonical_writes,
            vec![
                ("delete".to_owned(), 1),
                ("delete".to_owned(), 2),
                ("insert".to_owned(), 1),
                ("insert".to_owned(), 2),
                ("insert".to_owned(), 3),
            ]
        );
        let inserted_header_count: u32 = live_store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM conditional_reorg_header_audit",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(inserted_header_count, 3);
        assert_eq!(live_store.best_hash(), Some(b3.hash));
        assert_eq!(live_store.sync_generation().unwrap(), 51);
        assert_eq!(live_store.canonical_hash(Height(0)), Some(genesis.hash));
        assert_eq!(live_store.canonical_hash(Height(1)), Some(b1.hash));
        assert_eq!(live_store.canonical_hash(Height(2)), Some(b2.hash));
        assert_eq!(live_store.canonical_hash(Height(3)), Some(b3.hash));
        assert_eq!(live_store.get_header(a1.hash), Some(a1));
        assert_eq!(live_store.get_header(a2.hash), Some(a2));

        live_store.flush().unwrap();
        cleanup_db_path(&staged_path);
        cleanup_db_path(&live_path);
    }

    #[test]
    fn sqlite_snapshot_delta_handles_reorg_and_shorter_canonical_chain() {
        let live_path = temp_db_path("snapshot-reorg-live");
        let shorter_path = temp_db_path("snapshot-reorg-shorter");
        let reorg_path = temp_db_path("snapshot-reorg-staged");

        let live_store = SqliteHeaderStore::open(&live_path).unwrap();
        let mut live_chain = permissive_chain(live_store);
        let genesis = live_chain
            .insert_genesis(BlockHeader::mainnet_genesis())
            .unwrap();
        let a1 = live_chain
            .insert_header(low_difficulty_child(&genesis, 27))
            .unwrap();
        let live_store = live_chain.into_store();
        live_store.snapshot_to(&shorter_path).unwrap();

        let mut live_chain = permissive_chain(live_store);
        let a2 = live_chain
            .insert_header(low_difficulty_child(&a1, 28))
            .unwrap();
        let mut live_store = live_chain.into_store();
        live_store.snapshot_to(&reorg_path).unwrap();

        let (b1, b2, b3) = {
            let staged_store = SqliteHeaderStore::open(&reorg_path).unwrap();
            let mut staged_chain = permissive_chain(staged_store);
            let b1 = staged_chain
                .insert_header(low_difficulty_child(&genesis, 29))
                .unwrap();
            let b2 = staged_chain
                .insert_header(low_difficulty_child(&b1, 30))
                .unwrap();
            let b3 = staged_chain
                .insert_header(low_difficulty_child(&b2, 31))
                .unwrap();
            staged_chain.into_store().flush().unwrap();
            (b1, b2, b3)
        };

        live_store.publish_snapshot_from(&reorg_path).unwrap();
        assert_eq!(live_store.best_hash(), Some(b3.hash));
        assert_eq!(live_store.canonical_hash(Height(0)), Some(genesis.hash));
        assert_eq!(live_store.canonical_hash(Height(1)), Some(b1.hash));
        assert_eq!(live_store.canonical_hash(Height(2)), Some(b2.hash));
        assert_eq!(live_store.canonical_hash(Height(3)), Some(b3.hash));
        assert_eq!(live_store.get_header(a2.hash), Some(a2));

        live_store.publish_snapshot_from(&shorter_path).unwrap();
        assert_eq!(live_store.best_hash(), Some(a1.hash));
        assert_eq!(live_store.canonical_hash(Height(0)), Some(genesis.hash));
        assert_eq!(live_store.canonical_hash(Height(1)), Some(a1.hash));
        assert_eq!(live_store.canonical_hash(Height(2)), None);
        assert_eq!(live_store.canonical_hash(Height(3)), None);
        assert_eq!(live_store.get_header(b3.hash), Some(b3));

        live_store.flush().unwrap();
        cleanup_db_path(&reorg_path);
        cleanup_db_path(&shorter_path);
        cleanup_db_path(&live_path);
    }

    #[test]
    fn sqlite_snapshot_publication_atomically_replaces_live_chain_state() {
        let live_path = temp_db_path("snapshot-live");
        let staged_path = temp_db_path("snapshot-staged");

        let live_store = SqliteHeaderStore::open(&live_path).unwrap();
        let mut live_chain = permissive_chain(live_store);
        let genesis = live_chain
            .insert_genesis(BlockHeader::mainnet_genesis())
            .unwrap();
        let live_tip = live_chain
            .insert_header(low_difficulty_child(&genesis, 21))
            .unwrap();
        let mut live_store = live_chain.into_store();
        live_store.set_sync_generation(7).unwrap();
        live_store.snapshot_to(&staged_path).unwrap();

        let staged_tip = {
            let staged_store = SqliteHeaderStore::open(&staged_path).unwrap();
            let mut staged_chain = permissive_chain(staged_store);
            let staged_tip = staged_chain
                .insert_header(low_difficulty_child(&live_tip, 22))
                .unwrap();
            let mut staged_store = staged_chain.into_store();
            staged_store.set_sync_generation(8).unwrap();
            staged_store.flush().unwrap();
            staged_tip
        };

        let mut observer = SqliteHeaderStore::open(&live_path).unwrap();
        assert_eq!(live_store.best_hash(), Some(live_tip.hash));
        assert_eq!(live_store.sync_generation().unwrap(), 7);
        assert_eq!(observer.best_hash(), Some(live_tip.hash));
        assert_eq!(observer.sync_generation().unwrap(), 7);
        assert_eq!(live_store.canonical_hash(Height(2)), None);
        assert_eq!(live_store.get_header(staged_tip.hash), None);

        let observer_transaction = observer.connection.transaction().unwrap();
        let observed_best_before: Vec<u8> = observer_transaction
            .query_row(
                "SELECT value FROM chain_state WHERE key = 'best_hash'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(observed_best_before, live_tip.hash.as_bytes());

        live_store.publish_snapshot_from(&staged_path).unwrap();

        assert_eq!(live_store.best_hash(), Some(staged_tip.hash));
        assert_eq!(live_store.sync_generation().unwrap(), 8);
        let observed_best_during: Vec<u8> = observer_transaction
            .query_row(
                "SELECT value FROM chain_state WHERE key = 'best_hash'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(observed_best_during, live_tip.hash.as_bytes());
        observer_transaction.commit().unwrap();
        assert_eq!(observer.best_hash(), Some(staged_tip.hash));
        assert_eq!(observer.sync_generation().unwrap(), 8);
        assert_eq!(live_store.canonical_hash(Height(2)), Some(staged_tip.hash));
        assert_eq!(live_store.get_header(staged_tip.hash), Some(staged_tip));
        let journal_mode: String = live_store
            .connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(journal_mode, "wal");

        observer.flush().unwrap();
        live_store.flush().unwrap();
        cleanup_db_path(&staged_path);
        cleanup_db_path(&live_path);
    }

    #[test]
    fn sqlite_snapshot_rejects_existing_destination_and_missing_source() {
        let live_path = temp_db_path("snapshot-path-live");
        let staged_path = temp_db_path("snapshot-path-stage");
        let missing_path = temp_db_path("snapshot-path-missing");
        let mut store = SqliteHeaderStore::open(&live_path).unwrap();
        std::fs::write(&staged_path, b"occupied").unwrap();

        assert_eq!(
            store.snapshot_to(&staged_path).unwrap_err(),
            ChainError::Storage("snapshot destination already exists".to_owned())
        );
        assert!(
            store
                .publish_snapshot_from(&missing_path)
                .unwrap_err()
                .to_string()
                .contains("could not inspect snapshot source")
        );

        store.flush().unwrap();
        cleanup_db_path(&missing_path);
        cleanup_db_path(&staged_path);
        cleanup_db_path(&live_path);
    }

    #[test]
    fn best_chain_extension_promotes_only_new_tip() {
        let mut chain = permissive_chain(CountingHeaderStore::default());
        let genesis = chain
            .insert_genesis(BlockHeader::mainnet_genesis())
            .unwrap();
        let child = chain
            .insert_header(low_difficulty_child(&genesis, 11))
            .unwrap();
        let store = chain.into_store();

        assert_eq!(store.full_replacements, 1);
        assert_eq!(store.tip_promotions, 1);
        assert_eq!(store.inner.canonical_hash(Height(0)), Some(genesis.hash));
        assert_eq!(store.inner.canonical_hash(Height(1)), Some(child.hash));
        assert_eq!(store.inner.best_hash(), Some(child.hash));
    }

    #[test]
    fn batch_chain_extension_uses_one_batch_put_and_promotion() {
        let mut chain = permissive_chain(CountingHeaderStore::default());
        let genesis = chain
            .insert_genesis(BlockHeader::mainnet_genesis())
            .unwrap();
        let child_header = low_difficulty_child(&genesis, 14);
        let child_stub = StoredHeader {
            hash: child_header.hash(),
            header: child_header.clone(),
            height: Height(1),
            chainwork: Chainwork::zero(),
        };
        let grandchild_header = low_difficulty_child(&child_stub, 15);
        let accepted = chain
            .insert_headers([child_header, grandchild_header])
            .unwrap();
        let store = chain.into_store();

        assert_eq!(accepted.len(), 2);
        assert_eq!(store.full_replacements, 1);
        assert_eq!(store.batch_puts, 1);
        assert_eq!(store.batch_tip_promotions, 1);
        assert_eq!(store.tip_promotions, 0);
        assert_eq!(store.inner.canonical_hash(Height(0)), Some(genesis.hash));
        assert_eq!(
            store.inner.canonical_hash(Height(1)),
            Some(accepted[0].hash)
        );
        assert_eq!(
            store.inner.canonical_hash(Height(2)),
            Some(accepted[1].hash)
        );
        assert_eq!(store.inner.best_hash(), Some(accepted[1].hash));
    }

    #[test]
    #[ignore = "requires HNS_CHAIN_BENCHMARK_DB to name a complete mainnet headers.sqlite"]
    fn sqlite_mainnet_plus_one_delta_publication_benchmark() {
        const BASELINE_GENERATION: u64 = 70;

        let source_path = std::env::var_os("HNS_CHAIN_BENCHMARK_DB")
            .map(std::path::PathBuf::from)
            .expect("HNS_CHAIN_BENCHMARK_DB must name a complete mainnet headers.sqlite");
        let live_path = temp_db_path("mainnet-delta-benchmark-live");
        let staged_path = temp_db_path("mainnet-delta-benchmark-stage");

        let setup_started = std::time::Instant::now();
        let source_store = SqliteHeaderStore::open(&source_path).unwrap();
        source_store.snapshot_to(&live_path).unwrap();
        source_store.flush().unwrap();
        let mut live_store = SqliteHeaderStore::open(&live_path).unwrap();
        let original_tip_hash = live_store.best_hash().expect("benchmark source has a tip");
        let original_tip = live_store
            .get_header(original_tip_hash)
            .expect("benchmark source stores its tip");
        assert!(original_tip.height.0 > 0, "benchmark source has history");
        let baseline_tip_hash = live_store
            .canonical_hash(Height(original_tip.height.0 - 1))
            .expect("benchmark source has the tip parent");
        let transaction = live_store.connection.transaction().unwrap();
        transaction
            .execute(
                "DELETE FROM hash_by_height WHERE height = ?1",
                params![original_tip.height.0],
            )
            .unwrap();
        transaction
            .execute(
                "DELETE FROM headers_by_hash WHERE hash = ?1",
                params![original_tip_hash.as_bytes().as_slice()],
            )
            .unwrap();
        transaction
            .execute(
                "
                INSERT INTO chain_state(key, value)
                VALUES ('best_hash', ?1)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                ",
                params![baseline_tip_hash.as_bytes().as_slice()],
            )
            .unwrap();
        transaction.commit().unwrap();
        live_store.set_sync_generation(BASELINE_GENERATION).unwrap();
        let setup_elapsed = setup_started.elapsed();

        let preparation_started = std::time::Instant::now();
        live_store.snapshot_to(&staged_path).unwrap();
        live_store.flush().unwrap();
        let mut staged_store = SqliteHeaderStore::open(&staged_path).unwrap();
        staged_store
            .begin_snapshot_publication_delta(BASELINE_GENERATION, Some(baseline_tip_hash))
            .unwrap();
        staged_store.flush().unwrap();
        let preparation_elapsed = preparation_started.elapsed();

        let staged_delta_started = std::time::Instant::now();
        let staged_store = SqliteHeaderStore::open(&staged_path).unwrap();
        let mut staged_chain = HeaderChain::new(staged_store);
        let restored_tip = staged_chain
            .insert_header(original_tip.header.clone())
            .unwrap();
        assert_eq!(restored_tip, original_tip);
        let mut staged_store = staged_chain.into_store();
        staged_store
            .set_sync_generation(BASELINE_GENERATION + 1)
            .unwrap();
        staged_store.flush().unwrap();
        let staged_delta_elapsed = staged_delta_started.elapsed();

        let mut live_store = SqliteHeaderStore::open(&live_path).unwrap();
        let final_window_started = std::time::Instant::now();
        assert!(
            live_store
                .publish_snapshot_from_if_current(
                    &staged_path,
                    BASELINE_GENERATION,
                    Some(baseline_tip_hash),
                )
                .unwrap()
        );
        let final_window_elapsed = final_window_started.elapsed();
        assert_eq!(live_store.best_hash(), Some(original_tip_hash));
        assert_eq!(
            live_store.sync_generation().unwrap(),
            BASELINE_GENERATION + 1
        );
        live_store.flush().unwrap();

        eprintln!(
            "mainnet_delta_benchmark setup_us={} preparation_us={} staged_plus_one_us={} final_publication_window_us={}",
            setup_elapsed.as_micros(),
            preparation_elapsed.as_micros(),
            staged_delta_elapsed.as_micros(),
            final_window_elapsed.as_micros(),
        );

        cleanup_db_path(&staged_path);
        cleanup_db_path(&live_path);
    }

    #[derive(Default)]
    struct CountingHeaderStore {
        inner: MemoryHeaderStore,
        full_replacements: usize,
        tip_promotions: usize,
        batch_puts: usize,
        batch_tip_promotions: usize,
    }

    impl HeaderStore for CountingHeaderStore {
        fn get_header(&self, hash: Hash) -> Option<StoredHeader> {
            self.inner.get_header(hash)
        }

        fn put_header(&mut self, header: StoredHeader) -> Result<(), ChainError> {
            self.inner.put_header(header)
        }

        fn put_headers(&mut self, headers: &[StoredHeader]) -> Result<(), ChainError> {
            self.batch_puts += 1;
            self.inner.put_headers(headers)
        }

        fn best_hash(&self) -> Option<Hash> {
            self.inner.best_hash()
        }

        fn canonical_hash(&self, height: Height) -> Option<Hash> {
            self.inner.canonical_hash(height)
        }

        fn promote_canonical_tip(&mut self, header: &StoredHeader) -> Result<(), ChainError> {
            self.tip_promotions += 1;
            self.inner.promote_canonical_tip(header)
        }

        fn promote_canonical_tips(&mut self, headers: &[StoredHeader]) -> Result<(), ChainError> {
            self.batch_tip_promotions += 1;
            self.inner.promote_canonical_tips(headers)
        }

        fn replace_canonical_chain(&mut self, headers: &[StoredHeader]) -> Result<(), ChainError> {
            self.full_replacements += 1;
            self.inner.replace_canonical_chain(headers)
        }
    }

    fn permissive_chain<S: HeaderStore>(store: S) -> HeaderChain<S> {
        HeaderChain::with_difficulty_policy(store, DifficultyPolicy::Permissive)
    }

    fn seeded_mainnet_chain_with_spacing(spacing: u64) -> HeaderChain<MemoryHeaderStore> {
        let mut store = MemoryHeaderStore::default();
        let genesis_header = BlockHeader::mainnet_genesis();
        let mut previous = StoredHeader {
            hash: genesis_header.hash(),
            chainwork: Chainwork::from_bits(genesis_header.bits).unwrap(),
            header: genesis_header,
            height: Height(0),
        };
        store.put_header(previous.clone()).unwrap();
        store.promote_canonical_tip(&previous).unwrap();

        for height in 1..=MAINNET_BLOCKS_PER_DAY + 2 {
            let mut header = BlockHeader::mainnet_genesis();
            header.prev_block = previous.hash;
            header.time = previous.header.time + spacing;
            header.extra_nonce[..4].copy_from_slice(&height.to_le_bytes());
            let chainwork = previous
                .chainwork
                .checked_add(&Chainwork::from_bits(header.bits).unwrap());
            let stored = StoredHeader {
                hash: header.hash(),
                header,
                height: Height(height),
                chainwork,
            };
            store.put_header(stored.clone()).unwrap();
            store.promote_canonical_tip(&stored).unwrap();
            previous = stored;
        }

        HeaderChain::new(store)
    }

    fn low_difficulty_child(parent: &StoredHeader, salt: u8) -> BlockHeader {
        let mut child = BlockHeader::mainnet_genesis();
        child.prev_block = parent.hash;
        child.bits = 0x207f_ffff;
        child.time = parent.header.time + u64::from(salt) + 1;
        child.extra_nonce[0] = salt;

        for nonce in 0..100_000 {
            child.nonce = nonce;
            if verify_pow(child.hash(), child.bits).unwrap() {
                return child;
            }
        }

        panic!("could not find low-difficulty header nonce");
    }

    fn temp_db_path(label: &str) -> std::path::PathBuf {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "hns-chain-{label}-{}-{now}.sqlite",
            std::process::id()
        ))
    }

    fn cleanup_db_path(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
    }
}
