//! Iterable Bloom Lookup Table
//! see: https://dash.harvard.edu/bitstream/handle/1/14398536/GENTILI-SENIORTHESIS-2015.pdf

use std::collections::vec_deque::VecDeque;
use std::io::Write;
use std::error::Error;
use std::fmt;

use bitcoin_hashes::siphash24;
use byteorder::{WriteBytesExt, BigEndian,ByteOrder};
use std::cmp::min;

const ID_LEN:usize = 32;

#[derive(Clone)]
pub struct IBLT {
    buckets: Vec<Bucket>,
    k0: u64,
    k1: u64,
    k: usize,
    ksequence: Vec<(u64, u64)>
}

#[derive(Default,Clone)]
struct Bucket {
    keysum: [u8; ID_LEN],
    keyhash: u64,
    counter: i32
}

impl IBLT {

    pub fn generate_ksequence(k: usize, mut k0: u64, mut k1: u64) -> Vec<(u64, u64)> {
        let mut ksequence = Vec::new();
        let mut buf = [0u8;8];
        for _ in 0..k {
            ksequence.push((k0, k1));
            BigEndian::write_u64(&mut buf[0..8], k0);
            k0 = siphash24::Hash::hash_to_u64_with_keys(k0, k1, &buf);
            BigEndian::write_u64(&mut buf[0..8], k1);
            k1 = siphash24::Hash::hash_to_u64_with_keys(k0, k1, &buf);
        }
        ksequence
    }

    /// Create a new IBLT with m buckets and k hash functions
    pub fn new (m: usize, k: usize, k0: u64, k1: u64) -> IBLT {
        IBLT{buckets: vec![Bucket::default();m], k0, k1, k,
            ksequence: Self::generate_ksequence(k+1, k0, k1)}
    }

    fn hash (&self, n: usize, id: &[u8]) -> u64 {
        let (k0, k1) = self.ksequence[n];
        siphash24::Hash::hash_to_u64_with_keys(k0, k1, id)
    }

    /// insert an id
    pub fn insert (&mut self, id: &[u8]) {
        assert_eq!(id.len(), ID_LEN);
        let keyhash = self.hash(0, id);
        let mut hash = self.k0;
        for i in 0..self.k {
            hash = self.hash(i+1, id);
            let n = IBLT::fast_reduce(hash, self.buckets.len());
            let ref mut bucket = self.buckets[n];
            for i in 0..id.len () {
                bucket.keysum[i] ^= id[i];
            }
            bucket.counter += 1;
            bucket.keyhash ^= keyhash;
        }
    }

    /// delete an id
    pub fn delete (&mut self, id: &[u8]) {
        assert_eq!(id.len(), ID_LEN);
        let keyhash = self.hash(0, id);
        let mut hash = self.k0;
        for i in 0..self.k {
            hash = self.hash(i+1, id);
            let n = IBLT::fast_reduce(hash, self.buckets.len());
            let ref mut bucket = self.buckets[n];
            for i in 0..id.len () {
                bucket.keysum[i] ^= id[i];
            }
            bucket.counter -= 1;
            bucket.keyhash ^= keyhash;
        }
    }

    /// iterate over ids. This preserves the IBLT as it makes a copy internally
    pub fn iter(&self) -> IBLTIterator {
        IBLTIterator::new(self.clone())
    }

    /// iterare over ids. This destroys the IBLT
    pub fn into_iter (self) -> IBLTIterator {
        IBLTIterator::new(self)
    }

    /// substract an other IBLT from this and return the result
    pub fn substract (self, other: IBLT) -> IBLT  {
        assert_eq!(self.buckets.len(), other.buckets.len());
        assert_eq!(self.k0, other.k0);
        assert_eq!(self.k1, other.k1);
        assert_eq!(self.k, other.k);
        let mut buckets = vec![Bucket::default(); self.buckets.len()];
        for (i, b) in buckets.iter_mut().enumerate() {
            let ref sb = self.buckets[i];
            let ref ob = other.buckets[i];
            b.keyhash = sb.keyhash ^ ob.keyhash;
            for (j, c) in b.keysum.iter_mut().enumerate() {
                *c = sb.keysum[j] ^ ob.keysum[j];
            }
            b.counter = sb.counter - ob.counter;
        }
        IBLT{buckets, k0: self.k0, k1: self.k1, k: self.k, ksequence: self.ksequence}
    }

    fn fast_reduce (n: u64, r: usize) -> usize {
        ((n as u128 * r as u128) >> 64) as usize
    }
}

/// compute a min sketch of k size
pub fn min_sketch(k:usize, k0: u64, k1: u64, ids: &mut Iterator<Item=[u8; ID_LEN]>) -> Vec<u16> {
    let ksequence = IBLT::generate_ksequence(k, k0, k1);
    let mut min_hashes = vec![0xffff; k];
    for id in ids {
        for i in 0..k {
            min_hashes[k] = min(min_hashes[k],
                                siphash24::Hash::hash_to_u64_with_keys(k0, k1, &id) as u16);
        }
    }
    min_hashes
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
pub enum IBLTEntry {
    Inserted([u8; ID_LEN]),
    Deleted([u8; ID_LEN])
}

pub struct IBLTIterator {
    iblt: IBLT,
    queue: VecDeque<usize>,
    incomplete: bool
}

impl IBLTIterator {
    pub fn new (iblt: IBLT) -> IBLTIterator {
        let mut queue = VecDeque::new();
        for (i, bucket) in iblt.buckets.iter().enumerate() {
            if bucket.counter.abs() == 1 &&
                bucket.keyhash == iblt.hash(0, &bucket.keysum[..]) {
                queue.push_back(i);
            }
        }
        IBLTIterator{iblt, queue, incomplete: false}
    }
}

impl Iterator for IBLTIterator {
    type Item = Result<IBLTEntry, IBLTError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.incomplete {
            return None;
        }
        while let Some(i) = self.queue.pop_front() {
            let c = self.iblt.buckets[i].counter;
            if c.abs() == 1 {
                let id = self.iblt.buckets[i].keysum;
                let keyhash = self.iblt.hash(0, &id[..]);
                let found = c.abs() == 1 && keyhash == self.iblt.buckets[i].keyhash;
                let mut hash = self.iblt.k0;
                for i in 0..self.iblt.k {
                    hash = self.iblt.hash(i+1, &id[..]);
                    let n = IBLT::fast_reduce(hash, self.iblt.buckets.len());
                    {
                        let ref mut bucket = self.iblt.buckets[n];
                        for i in 0..id.len() {
                            bucket.keysum[i] ^= id[i];
                        }
                        bucket.counter -= c;
                        bucket.keyhash ^= keyhash;
                    }
                    let ref bucket = self.iblt.buckets[n];
                    if bucket.counter.abs() == 1 &&
                        self.iblt.hash(0, &bucket.keysum[..]) == bucket.keyhash {
                        self.queue.push_back(n);
                    }
                }
                if found {
                    if c == 1 {
                        return Some(Ok(IBLTEntry::Inserted(id)));
                    }
                    else {
                        return Some(Ok(IBLTEntry::Deleted(id)));
                    }
                }
            }
        }
        for bucket in &self.iblt.buckets {
            if bucket.counter != 0  {
                self.incomplete = true;
                return Some(Err(IBLTError::IncompleteIteration));
            }
        }
        None
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::collections::HashSet;

    #[test]
    pub fn test_single_insert () {
        let mut a = IBLT::new(10, 3, 0, 0);

        a.insert(&[1; ID_LEN]);
        assert_eq!(a.iter().next().unwrap().unwrap(), IBLTEntry::Inserted([1; ID_LEN]));
    }

    #[test]
    pub fn test_single_insert_delete () {
        let mut a = IBLT::new(10, 3, 0, 0);

        a.insert(&[1; ID_LEN]);
        a.delete(&[1; ID_LEN]);
        assert!(a.iter().next().is_none());
    }

    #[test]
    pub fn test_few_inserts () {
        let mut a = IBLT::new(1000, 3, 0, 0);

        let mut set = HashSet::new();
        for i in 0..20 {
            set.insert([i; ID_LEN]);
            a.insert(&[i; ID_LEN]);
        }

        for id in a.iter().map(|e| e.unwrap()) {
            if let IBLTEntry::Inserted(id) = id {
                assert!(set.remove(&id));
            }
        }
        assert!(set.is_empty());
    }

    #[test]
    pub fn test_few_inserts_deletes () {
        let mut a = IBLT::new(1000, 3, 0, 0);

        let mut inserted = HashSet::new();
        let mut removed = HashSet::new();
        for i in 0..20 {
            inserted.insert([i; ID_LEN]);
            a.insert(&[i; ID_LEN]);
        }
        for i in 10 .. 30 {
            removed.insert([i; ID_LEN]);
            a.delete(&[i; ID_LEN]);
        }

        let mut remained = inserted.difference(&removed).collect::<HashSet<_>>();

        for id in a.iter() {
            if let IBLTEntry::Inserted(id) = id.unwrap() {
                assert!(remained.remove(&id));
            }
        }
        assert!(remained.is_empty());

        let mut deleted = removed.difference(&inserted).collect::<HashSet<_>>();
        for id in a.iter() {
            if let IBLTEntry::Deleted(id) = id.unwrap() {
                assert!(deleted.remove(&id));
            }
        }
        assert!(deleted.is_empty());
    }

    #[test]
    pub fn test_substract() {
        let mut a = IBLT::new(1000, 3, 0, 0);

        let mut a_inserted = HashSet::new();
        for i in 0..20 {
            a_inserted.insert([i; ID_LEN]);
            a.insert(&[i; ID_LEN]);
        }

        let mut b = IBLT::new(1000, 3, 0, 0);

        let mut b_inserted = HashSet::new();
        for i in 15..30 {
            b_inserted.insert([i; ID_LEN]);
            b.insert(&[i; ID_LEN]);
        }
        let c = a.substract(b);
        assert_eq!(c.iter().filter(|r| if let Ok(IBLTEntry::Inserted(_)) = r { true } else {false} ).count(), 15);
        assert_eq!(c.into_iter().filter(|r| if let Ok(IBLTEntry::Deleted(_)) = r { true } else {false} ).count(), 10);
    }

    #[test]
    pub fn test_overload() {
        let mut a = IBLT::new(10, 5, 0, 0);
        for i in 0..20 {
            a.insert(&[i; ID_LEN]);
        }
        assert!(a.into_iter().any(|r|  r.is_err()));
    }
}