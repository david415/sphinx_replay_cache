// mix_key.rs - Mix key logistics.
// Copyright (C) 2018  David Anthony Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

//!
//! This module handles Sphinx packet replay detection and storing the mix
//! key and it's associated metadata. To quoate "Sphinx Mix Network Cryptographic
//! Packet Format Specification", section "6. Sphinx Packet Processing" states
//! the following:
//!
//!   "After a packet has been unwrapped successfully, a replay detection
//!   tag is checked to ensure that the packet has not been seen before.
//!   If the packet is a replay, the packet MUST be discarded with no
//!   additional processing."
//!
//! Note: 1Gbps ethernet line speed is 118 MB/s and 123 MB/s with jumbo frames
//! therefore to be on the safe side we can set the line rate to:
//!    128974848 = 123 * 1024 * 1024.
//!

#[macro_use]
extern crate log;

extern crate sled;
extern crate bloom;
extern crate rand;
extern crate byteorder;

extern crate sphinxcrypto;
extern crate ecdh_wrapper;
extern crate epoch;

pub mod errors;
pub mod constants;

use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::path::Path;
use std::sync::{Arc, Mutex};

use self::byteorder::{ByteOrder, LittleEndian};

use self::rand::os::OsRng;

use sled::Tree;
use bloom::{ASMS,BloomFilter};

use sphinxcrypto::constants::{SPHINX_REPLAY_TAG_SIZE, PACKET_SIZE};
use ecdh_wrapper::{PublicKey, PrivateKey};
use epoch::Clock;

use errors::MixKeyError;
use constants::MIX_KEY_FLUSH_FREQUENCY;


const MIX_CACHE_KEY: &str = "private_key";
const EPOCH_KEY: &str = "epoch";


pub struct MixKeys {
    keys: Arc<Mutex<HashMap<u64, Arc<Mutex<MixKey>>>>>,
    clock: Clock,
    num_mix_keys: u8,
    base_dir: String,
    line_rate: u64,
}

impl MixKeys {
    pub fn new(clock: Clock, num_mix_keys: u8, base_dir: String, line_rate: u64) -> Result<Self, MixKeyError> {
        let mut m = MixKeys{
            keys: Arc::new(Mutex::new(HashMap::new())),
            clock: clock,
            num_mix_keys: num_mix_keys,
            base_dir: base_dir,
            line_rate: line_rate,
        };
        m.init()?;
        Ok(m)
    }

    /// Generate or load the initial set of MixKey.
    fn init(&mut self) -> Result<(), MixKeyError> {
        let time = self.clock.now();
        let _ = self.generate(time.epoch)?;
        // Clean up stale mix keys.
        // XXX...
        Ok(())
    }

    pub fn generate(&mut self, base_epoch: u64) -> Result<bool, MixKeyError> {
        let mut did_generate = false;
        for epoch in base_epoch..base_epoch+self.num_mix_keys as u64{
            if let Some(_key) = self.keys.lock().unwrap().get(&epoch) {
                continue
            }
            let key = Arc::new(Mutex::new(MixKey::new(self.line_rate, epoch, self.clock.period(), &self.base_dir)?));
            did_generate = true;
            self.keys.lock().unwrap().insert(epoch, key);
        }
        Ok(did_generate)
    }

    pub fn prune(&mut self) -> bool {
        let mut did_prune = false;
        let time = self.clock.now();
        self.keys.lock().unwrap().retain(|key, _value| {
            if *key < time.epoch - 1 {
                did_prune = true;
                return true
            }
            return false
        });
        did_prune
    }

    pub fn public_key(&self, epoch: u64) -> Option<PublicKey> {
        if let Some(ref key) = self.keys.lock().unwrap().get(&epoch) {
            let k = key.lock().unwrap().public_key();
            return Some(k)
        }
        None
    }

    pub fn shadow(&mut self, dst: &mut HashMap<u64, Arc<Mutex<MixKey>>>) {
        dst.retain(|key, _value| {
            self.keys.lock().unwrap().contains_key(key)
        });
        for (key, val) in self.keys.lock().unwrap().iter() {
            if !dst.contains_key(&key) {
                dst.insert(*key, val.clone());
            }
        }
    }
}



#[derive(PartialEq, Eq, Hash)]
pub struct Tag([u8; SPHINX_REPLAY_TAG_SIZE]);

impl Tag {
    fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl Clone for Tag {
    fn clone(&self) -> Tag {
        Tag(self.0)
    }
}

pub struct MixKey {
    filter: BloomFilter<RandomState, RandomState>,
    cache: Tree,
    private_key: PrivateKey,
    epoch: u64,
}

impl MixKey {
    pub fn new(line_rate: u64, epoch: u64, epoch_duration: u64, base_dir: &String) -> Result<MixKey, MixKeyError> {
        let false_positive_rate: f32 = 0.01;
        let expected_num_items: u32 = (line_rate as f64 / PACKET_SIZE as f64) as u32 * epoch_duration as u32;
        let cache_capacity: usize = (((epoch_duration * line_rate) / PACKET_SIZE as u64) as usize * SPHINX_REPLAY_TAG_SIZE) / 2;

        let cache_cfg_builder = sled::ConfigBuilder::default()
            .path(Path::new(base_dir).join(format!("mix_key.{}", epoch)))
            .cache_capacity(cache_capacity)
            .use_compression(false)
            .flush_every_ms(Some(MIX_KEY_FLUSH_FREQUENCY))
            .snapshot_after_ops(100_000); // XXX
        let cache_cfg = cache_cfg_builder.build();

        let cache = match Tree::start(cache_cfg) {
            Ok(x) => x,
            Err(e) => {
                print!("create cache failed: {}", e);
                return Err(MixKeyError::CreateCacheFailed);
            },
        };

        if let Ok(Some(raw_epoch)) = cache.get(EPOCH_KEY.to_string().as_bytes()) {
            let stored_epoch = LittleEndian::read_u64(&raw_epoch);
            if epoch != stored_epoch {
                warn!("mix key mismatched epoch during load.");
                return Err(MixKeyError::LoadCacheFailed);
            }
        } else {
            let mut raw_epoch = vec![0u8; 8];
            LittleEndian::write_u64(&mut raw_epoch, epoch);
            if let Err(e) = cache.set(raw_epoch, vec![]) {
                warn!("mix key failed to set epoch in cache: {}", e);
                return Err(MixKeyError::SledError);
            }
        }

        let mut private_key = PrivateKey::default();
        if let Ok(Some(key_blob)) = cache.get(MIX_CACHE_KEY.to_string().as_bytes()) {
            private_key.load_bytes(&key_blob)?;
        } else {
            let mut rng = OsRng::new()?;
            private_key = PrivateKey::generate(&mut rng)?;
            if let Err(e) = cache.set(MIX_CACHE_KEY.as_bytes().to_vec(), private_key.to_vec()) {
                warn!("mix key failed to write to disk cache: {}", e);
                return Err(MixKeyError::CreateCacheFailed);
            }
        }

        Ok(MixKey{
            filter: BloomFilter::with_rate(false_positive_rate, expected_num_items),
            cache: cache,
            private_key: private_key,
            epoch: epoch,
        })
    }

    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    pub fn public_key(&self) -> PublicKey {
        self.private_key.public_key()
    }

    pub fn is_replay(&mut self, tag: Tag) -> Result<bool, MixKeyError> {
        let maybe_replay = self.filter.contains(&tag);
        if !maybe_replay {
            self.filter.insert(&tag);
            if let Ok(_v) = self.cache.set(tag.to_vec(), vec![]) {
                return Ok(false)
            } else {
                return Err(MixKeyError::SledError)
            }
        }
        if let Ok(_) = self.cache.get(&tag.0) {
            return Ok(true)
        } else {
            self.filter.insert(&tag);
            if let Ok(_v) = self.cache.set(tag.to_vec(), vec![]) {
                return Ok(false)
            } else {
                return Err(MixKeyError::SledError)
            }
        }
    }

    pub fn flush(&mut self) {
        self.cache.flush().unwrap()
    }
}

#[cfg(test)]
mod tests {

    extern crate tempfile;
    extern crate rand;

    use self::rand::Rng;
    use self::rand::os::OsRng;
    use self::tempfile::TempDir;
    use super::*;


    #[test]
    fn basic_mix_keys_test() {
        let clock = epoch::Clock::new_katzenpost();
        let base_dir = TempDir::new().unwrap().path().to_str().unwrap().to_string();
        let line_rate = 128974848;
        let mut mix_keys = MixKeys::new(clock, 3, base_dir, line_rate).unwrap();

        let mut local_keys: HashMap<u64, Arc<Mutex<MixKey>>> = HashMap::new();

        mix_keys.shadow(&mut local_keys);
        for (k, v) in mix_keys.keys.lock().unwrap().iter() {
            assert!(local_keys.contains_key(&k));
        }
    }

    #[test]
    fn basic_mix_key_test() {
        let cache_dir = TempDir::new().unwrap();
        {
            let cache_dir_path = cache_dir.path().clone();
            //let epoch_duration = 3 * 60 * 60; // 3 hours
            //let epoch_duration = 1 * 60 * 60; // 1 hours
            let epoch_duration = 1;
            let epoch = 1;
            let mut mix_key = MixKey::new(128974848, epoch, epoch_duration, &cache_dir_path.to_str().unwrap().to_string()).unwrap();
            let mut rng = OsRng::new().unwrap();
            let mut raw = [0u8; SPHINX_REPLAY_TAG_SIZE];
            rng.fill_bytes(&mut raw);
            let tag = Tag(raw);

            assert_eq!(mix_key.is_replay(tag.clone()).unwrap(), false);
            assert_eq!(mix_key.is_replay(tag.clone()).unwrap(), true);
            assert_eq!(mix_key.is_replay(tag).unwrap(), true);

            mix_key.flush();
            let mut priv_key = PrivateKey::default();
            priv_key.load_bytes(&mix_key.private_key().to_vec()).unwrap();
            drop(mix_key);

            let new_mix_key = MixKey::new(128974848, epoch, epoch_duration, &cache_dir_path.to_str().unwrap().to_string()).unwrap();
            assert_eq!(epoch, new_mix_key.epoch);
            assert_eq!(priv_key, *new_mix_key.private_key());
        }
        TempDir::close(cache_dir).unwrap();
    }
}
