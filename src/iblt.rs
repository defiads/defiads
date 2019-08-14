//
// Copyright 2019 Tamas Blummer
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

//! Invertible Bloom Lookup Table
//! see: https://dash.harvard.edu/bitstream/handle/1/14398536/GENTILI-SENIORTHESIS-2015.pdf

use std::collections::{
    hash_set::HashSet,
    vec_deque::VecDeque
};
use std::error::Error;
use std::fmt;
use std::hash::Hasher;

use byteorder::{BigEndian,ByteOrder};
use std::cmp::min;
use std::ops::BitXorAssign;

const K_MAX: usize = 6;

/// trait any key of an IBLT has to implement
pub trait IBLTKey : BitXorAssign + Copy + Clone + Eq + PartialEq + Default + std::hash::Hash {
    fn hash_to_u64_with_keys (&self, k0: u64, k1: u64) -> u64;
}

/// an key set
pub trait IBLTKeySet<K : IBLTKey> {
    fn insert (&mut self, id: K) -> bool;
    fn remove(&mut self, id: &K) -> bool;
}

impl<K : IBLTKey> IBLTKeySet<K> for HashSet<K> {
    fn insert(&mut self, id: K) -> bool {
        self.insert(id)
    }

    fn remove(&mut self, id: &K) -> bool {
        self.remove(id)
    }
}

/// an invertible bloom lookup table
#[derive(Clone, Serialize, Deserialize)]
pub struct IBLT<K : IBLTKey> {
    buckets: Vec<Bucket<K>>,
    k0: u64,
    k1: u64,
    k: usize,
    ksequence: Vec<(u64, u64)>
}

impl<K: IBLTKey> fmt::Debug for IBLT<K> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "IBLT of size {}", self.k)
    }
}

#[derive(Default,Clone, Serialize, Deserialize)]
struct Bucket<K : IBLTKey> {
    keysum: K,
    hashsum: u64,
    count: i32
}

impl<K : IBLTKey> IBLT<K> {
    /// Create a new IBLT with m buckets and k hash functions
    pub fn new (m: u32, k: usize, k0: u64, k1: u64) -> IBLT<K> {
        assert!(k <= K_MAX);
        IBLT{buckets: vec![Bucket::default();m as usize], k0, k1, k,
            ksequence: generate_ksequence(k, k0, k1)}
    }

    pub fn len(&self) -> u32 {
        self.buckets.len() as u32
    }

    fn keyhash(&self, key: &K) -> u64 {
        key.hash_to_u64_with_keys(self.k0, self.k1)
    }

    fn buckets(&self, key: &K) -> BucketIterator {
        BucketIterator::new(self, key)
    }

    /// insert an id
    pub fn insert (&mut self, key: &K) {
        let keyhash = self.keyhash(key);
        for n in self.buckets(key) {
            let ref mut bucket = self.buckets[n];
            bucket.keysum ^= *key;
            bucket.count += 1;
            bucket.hashsum ^= keyhash;
        }
    }

    /// delete an id
    pub fn delete (&mut self, key: &K) {
        let keyhash = self.keyhash(key);
        for n in self.buckets(key) {
            let ref mut bucket = self.buckets[n];
            bucket.keysum ^= *key;
            bucket.count -= 1;
            bucket.hashsum ^= keyhash;
        }
    }

    /// iterate over ids. This preserves the IBLT as it makes a copy internally
    pub fn iter(&self) -> IBLTIterator<K> {
        IBLTIterator::new(self.clone())
    }

    /// iterare over ids. This destroys the IBLT
    pub fn into_iter (self) -> IBLTIterator<K> {
        IBLTIterator::new(self)
    }

    /// substract an other IBLT from this
    pub fn substract (&mut self, other: &IBLT<K>)  {
        assert_eq!(self.buckets.len(), other.buckets.len());
        assert_eq!(self.k0, other.k0);
        assert_eq!(self.k1, other.k1);
        assert_eq!(self.k, other.k);
        for (i, b) in self.buckets.iter_mut().enumerate() {
            let ref ob = other.buckets[i];
            b.hashsum ^= ob.hashsum;
            b.keysum ^= ob.keysum;
            b.count -= ob.count;
        }
    }

    #[cfg(test)]
    fn sync<S: IBLTKeySet<K>>(&self, other: &IBLT<K>, set: &mut S) -> Result<(), Box<dyn Error>> {
        let mut copy = self.clone();
        copy.substract(other);
        for e in copy.iter() {
            match e? {
                IBLTEntry::Inserted(ref id) => set.remove(id),
                IBLTEntry::Deleted(id) => set.insert(id)
            };
        }
        Ok(())
    }
}

/// compute a vector suitable to estimate set difference size
pub fn min_sketch(n:usize, k0: u64, k1: u64, ids: &mut dyn Iterator<Item=impl IBLTKey>) -> (Vec<u64>, Vec<(u64,u64)>, u32) {
    let ksequence = generate_ksequence(n, k0, k1);
    let mut min_hashes = vec![0xffffffffffffffff; n];
    let mut n_keys = 0;
    for id in ids {
        add_to_min_sketch(&mut min_hashes, &id, &ksequence);
        n_keys += 1;
    }
    (min_hashes, ksequence, n_keys)
}

pub fn add_to_min_sketch(min_hashes: &mut Vec<u64>, key: &impl IBLTKey, ksequence: &Vec<(u64, u64)>) {
    for (i, (k0, k1)) in ksequence.iter().enumerate() {
        min_hashes[i] = min(min_hashes[i], key.hash_to_u64_with_keys(*k0, *k1) as u64);
    }
}

/// estimate difference size from two known sketches and sizes
pub fn estimate_diff_size(sa: &[u64], al: u32, sb: &[u64], bl: u32) -> u32 {
    assert_eq!(sa.len(), sb.len());
    let k = sa.len();
    let r = sa.iter().zip(sb.iter()).filter(|(a, b)| *a == *b).count() as f32 / k as f32;
    ((1.0-r)/(1.0+r)*(al + bl) as f32) as u32
}



pub fn generate_ksequence(k: usize, mut k0: u64, mut k1: u64) -> Vec<(u64, u64)> {
    let mut ksequence = Vec::new();
    let mut buf = [0u8;8];
    for _ in 0..k {
        BigEndian::write_u64(&mut buf, k0);
        k0 = hash_slice_to_u64_with_keys(k0, k1, &buf);
        BigEndian::write_u64(&mut buf, k1);
        k1 = hash_slice_to_u64_with_keys(k0, k1, &buf);
        ksequence.push((k0, k1));
    }
    ksequence
}

fn hash_slice_to_u64_with_keys (k0: u64, k1: u64, s: &[u8]) -> u64 {
    let mut hasher = siphasher::sip::SipHasher::new_with_keys(k0, k1);
    hasher.write(s);
    hasher.finish()
}

struct BucketIterator {
    buckets: [usize; K_MAX],
    pos: usize,
    last: usize,
    k: usize
}

impl BucketIterator {
    fn new<K: IBLTKey> (iblt: &IBLT<K>, key: &K) -> BucketIterator {
        let mut buckets= [0usize; K_MAX];
        let len = iblt.buckets.len();
        for (i, (k0, k1)) in iblt.ksequence.iter().enumerate() {
            buckets [i] = key.hash_to_u64_with_keys(*k0, *k1) as usize % len;
        }
        let k = iblt.ksequence.len();
        buckets[0..k].sort();
        BucketIterator{buckets, pos: 0, last: 0, k}
    }
}

impl Iterator for BucketIterator {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos > 0 {
            while self.pos < self.k && self.last == self.buckets[self.pos] {
                self.pos += 1;
            }
        }
        if self.pos == self.k {
            return None;
        }
        self.last = self.buckets[self.pos];
        self.pos += 1;
        Some(self.last)
    }
}


#[derive(Debug)]
pub enum IBLTError {
    IncompleteIteration
}

impl Error for IBLTError {
    fn description(&self) -> &str {
        "Incomplete IBLT iteration"
    }
}

impl fmt::Display for IBLTError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.description())
    }
}

#[derive(Eq, PartialEq, Debug)]
pub enum IBLTEntry<K : IBLTKey> {
    Inserted(K),
    Deleted(K)
}

pub struct IBLTIterator<K : IBLTKey> {
    iblt: IBLT<K>,
    queue: VecDeque<usize>,
    incomplete: bool
}

impl<K: IBLTKey> IBLTIterator<K> {
    pub fn new (iblt: IBLT<K>) -> IBLTIterator<K> {
        let mut queue = VecDeque::new();
        for (i, bucket) in iblt.buckets.iter().enumerate() {
            if bucket.count.abs() == 1 &&
                bucket.hashsum == iblt.keyhash(&bucket.keysum) {
                queue.push_back(i);
            }
        }
        IBLTIterator{iblt, queue, incomplete: false}
    }
}

impl<K: IBLTKey> Iterator for IBLTIterator<K> {
    type Item = Result<IBLTEntry<K>, IBLTError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.incomplete {
            return None;
        }
        while let Some(i) = self.queue.pop_front() {
            let c = self.iblt.buckets[i].count;
            if c.abs() == 1 {
                let key = self.iblt.buckets[i].keysum;
                let keyhash = self.iblt.keyhash(&key);
                for n in self.iblt.buckets(&key) {
                    {
                        let ref mut bucket = self.iblt.buckets[n];
                        bucket.keysum ^= key;
                        bucket.hashsum ^= keyhash;
                        bucket.count -= c;
                    }
                    let ref bucket = self.iblt.buckets[n];
                    if bucket.count.abs() == 1 &&
                        self.iblt.keyhash(&bucket.keysum) == bucket.hashsum {
                        self.queue.push_back(n);
                    }
                }
                if c == 1 {
                    return Some(Ok(IBLTEntry::Inserted(key)));
                }
                else {
                    return Some(Ok(IBLTEntry::Deleted(key)));
                }
            }
        }
        for bucket in &self.iblt.buckets {
            if bucket.count != 0  {
                self.incomplete = true;
                return Some(Err(IBLTError::IncompleteIteration));
            }
        }
        None
    }
}

#[cfg(test)]
mod test {
    const ID_LEN: usize = 32;
    use super::*;
    use std::collections::HashSet;
    use crate::content::ContentKey;

    #[test]
    pub fn test_single_insert () {
        let mut a = IBLT::new(10, 3, 0, 0);

        a.insert(&ContentKey::new(&[1; ID_LEN]));
        assert_eq!(a.iter().next().unwrap().unwrap(), IBLTEntry::Inserted(ContentKey::new(&[1; ID_LEN])));
    }

    #[test]
    pub fn test_single_insert_delete () {
        let mut a = IBLT::new(10, 3, 0, 0);

        a.insert(&ContentKey::new(&[1; ID_LEN]));
        a.delete(&ContentKey::new(&[1; ID_LEN]));
        assert!(a.iter().next().is_none());
    }

    #[test]
    pub fn test_few_inserts () {
        let mut a = IBLT::new(35, 3,0, 0);

        let mut set = HashSet::new();
        for i in 0..20 {
            set.insert([i; ID_LEN]);
            a.insert(&ContentKey::new(&[i; ID_LEN]));
        }

        for id in a.iter().map(|e| e.unwrap()) {
            if let IBLTEntry::Inserted(id) = id {
                assert!(set.remove(&id.digest));
            }
        }
        assert!(set.is_empty());
    }

    #[test]
    pub fn test_few_inserts_deletes () {
        let mut a = IBLT::new(35, 3, 0, 0);

        let mut inserted = HashSet::new();
        let mut removed = HashSet::new();
        for i in 0..20 {
            inserted.insert([i; ID_LEN]);
            a.insert(&ContentKey::new(&[i; ID_LEN]));
        }
        for i in 10 .. 30 {
            removed.insert([i; ID_LEN]);
            a.delete(&ContentKey::new(&[i; ID_LEN]));
        }

        let mut remained = inserted.difference(&removed).collect::<HashSet<_>>();

        for id in a.iter() {
            if let IBLTEntry::Inserted(id) = id.unwrap() {
                assert!(remained.remove(&id.digest));
            }
        }
        assert!(remained.is_empty());

        let mut deleted = removed.difference(&inserted).collect::<HashSet<_>>();
        for id in a.iter() {
            if let IBLTEntry::Deleted(id) = id.unwrap() {
                assert!(deleted.remove(&id.digest));
            }
        }
        assert!(deleted.is_empty());
    }

    #[test]
    pub fn test_substract() {
        let mut a = IBLT::new(60, 3, 0, 0);

        let mut a_inserted = HashSet::new();
        for i in 0..20 {
            a_inserted.insert([i; ID_LEN]);
            a.insert(&ContentKey::new(&[i; ID_LEN]));
        }

        let mut b = IBLT::new(60, 3, 0, 0);

        let mut b_inserted = HashSet::new();
        for i in 15..30 {
            b_inserted.insert([i; ID_LEN]);
            b.insert(&ContentKey::new(&[i; ID_LEN]));
        }
        a.substract(&b);
        assert_eq!(a.iter().filter(|r| if let Ok(IBLTEntry::Inserted(_)) = r { true } else {false} ).count(), 15);
        assert_eq!(a.into_iter().filter(|r| if let Ok(IBLTEntry::Deleted(_)) = r { true } else {false} ).count(), 10);
    }

    #[test]
    pub fn test_overload() {
        let mut a = IBLT::new(10, 5, 0, 0);
        for i in 0..20 {
            a.insert(&ContentKey::new(&[i; ID_LEN]));
        }
        assert!(a.into_iter().any(|r|  r.is_err()));
    }

    #[test]
    pub fn test_sync () {
        use bitcoin_hashes::sha256;
        use bitcoin_hashes::Hash;

        let mut a = HashSet::new();
        let mut b = HashSet::new();

        let mut id = sha256::Hash::default();
        for i in 0..1000 {
            let mut t = [0u8; 32];
            t.copy_from_slice(&id[..]);
            if i >= 200 {
                a.insert(ContentKey::new(&t));
            }
            if i < 800 {
                b.insert(ContentKey::new(&t));
            }
            id = sha256::Hash::hash(&t);
        }

        let k0 = 0;
        let k1 = 0;

        let (a_sketch, _, _) = min_sketch(10, k0, k1, &mut a.iter().cloned());
        let al = a.len() as u32;

        let (b_sketch, _, _) = min_sketch(10, k0, k1, &mut b.iter().cloned());
        let bl = b.len() as u32;

        let buckets = estimate_diff_size(a_sketch.as_slice(), al, b_sketch.as_slice(), bl)*2;

        let mut a_iblt = IBLT::new(buckets, 4, k0, k1);
        for id in a.iter() {
            a_iblt.insert(id);
        }

        let mut b_iblt = IBLT::new(buckets, 4, k0, k1);
        for id in b.iter() {
            b_iblt.insert(id);
        }

        let mut a_copy = a.clone();
        a_iblt.sync(&b_iblt, &mut a_copy).unwrap();
        assert_eq!(a_copy, b);

        b_iblt.sync(&a_iblt, &mut b).unwrap();
        assert_eq!(b, a);
    }
}