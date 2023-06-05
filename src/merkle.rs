use sha2::{Sha256, Digest};
use core::array;
use serde::Serialize;
use std::{fmt::Debug, marker::PhantomData};

#[derive(Debug, Clone, Default)]
struct TrieNode<T> {
    substr: Vec<u8>,
    value: Option<T>,
    children: Option<Box<[Option<MerkleNode<T>>; 16]>>
}

#[derive(Debug, Clone)]
pub struct MerkleNode<T> {
    node: TrieNode<T>,
    commit: Option<[u8; 32]>
}

impl<T> MerkleNode<T> {
    fn empty_children_array() -> [Option<MerkleNode<T>>; 16] {
        array::from_fn(|_| None)
    }

    fn new(substr: Vec<u8>, value: Option<T>, children: Option<Box<[Option<MerkleNode<T>>; 16]>>) -> Self {
        MerkleNode {
            node: TrieNode {
                substr,
                value,
                children
            },
            commit: None
        }
    }
}

impl<T> Default for MerkleNode<T> {
    fn default() -> Self {
        MerkleNode {
            node: TrieNode {
                substr: Vec::default(),
                value: None,
                children: None
            },
            commit: None
        }
    }
}

impl<T: Serialize> MerkleNode<T> {
    fn prefix_len(a: &[u8], b: &[u8]) -> usize {
        let mut idx = 0;
        while idx < a.len() && idx < b.len() {
            if a[idx] != b[idx] { break; }
            idx += 1;
        }
        idx
    }

    // Make this node branch at cut_at, old data made into a child
    // Can always unwrap children after split call
    fn split(&mut self, cut_at: usize) {
        if cut_at < self.node.substr.len() {
            let suffix = self.node.substr.split_off(cut_at + 1);
            let mut children = Self::empty_children_array();
            children[self.node.substr[cut_at] as usize] = Some(Self::new(
                suffix, 
                self.node.value.take(),
                self.node.children.take()
            ));
            self.node.value = None;
            self.node.children = Some(Box::new(children));
            self.node.substr.truncate(cut_at);
        } else { 
            self.node.children.get_or_insert(Box::new(Self::empty_children_array()));
        }
        self.commit = None;
    }

    // If I only have one child and no value absorb it into me.
    // Otherwise do nothing.
    fn unsplit(&mut self) {
        if self.node.value.is_none() {
            if let Some(mut children) = self.node.children.take() {
                let mut some_iter = children.iter_mut().enumerate().filter_map(|(i, opt_g)| opt_g.as_mut().map(|g| (i, g)));
                let opt_child = some_iter.next();
                if let (Some((i, child)), None) = (opt_child, some_iter.next()) {
                    self.node.substr.push(i as u8);
                    self.node.substr.extend_from_slice(&child.node.substr);
                    self.node.children = child.node.children.take();
                    self.node.value = child.node.value.take();
                } else {
                    self.node.children = Some(children);
                }
            }
        }
        self.commit = None;
    }

    pub fn insert(&mut self, k: &[u8], v: T) -> Option<T> {
        let cut_at = Self::prefix_len(&k, &self.node.substr);
        if k.len() > cut_at {
            // Key forks from `substr` or key continues after `substr`
            self.split(cut_at);
            let suffix = &k[cut_at + 1..];
            let nibble = k[cut_at] as usize;
            if let Some(ref mut child) = self.node.children.as_mut().unwrap()[nibble] {
                child.insert(suffix, v)
            } else {
                self.node.children.as_mut().unwrap()[nibble] = Some(Self::new(
                    suffix.to_vec(), 
                    Some(v),
                    None
                ));
                None
            }
        } else {
            if self.node.substr.len() > cut_at {
                // Key contained in `substr`
                self.split(cut_at);
                self.node.value = Some(v);
                None
            } else {
                // Key is `substr`
                self.commit = None;
                self.node.value.replace(v)
            }
        }
    }

    fn remove(&mut self, k: &[u8]) -> Option<T> {
        let cut_at = Self::prefix_len(&k, &self.node.substr);
        if k.len() > cut_at { 
            if self.node.substr.len() > cut_at {
                // Key forks from `substr`
                None
            } else {
                // Key continues after `substr`
                if let Some(ref mut children) = self.node.children.as_mut() {
                    let suffix = &k[cut_at + 1..];
                    let nibble = k[cut_at] as usize;
                    if let Some(mut child) = children[nibble].take() {
                        self.commit = None;
                        let ret = child.remove(suffix);
                        if let (None, None) = (&child.node.children, &child.node.value) {
                            // child is empty, don't put it back.
                            if children.iter().filter(|g| g.is_some()).next().is_none() {
                                // children is empty, make it none.
                                self.node.children = None;
                            }
                        } else {
                            // child is non-empty, put it back.
                            children[nibble] = Some(child);
                        }
                        self.unsplit();
                        ret
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        } else {
            if self.node.substr.len() > cut_at {
                // Key contained in `substr`
                None
            } else {
                // Key is `substr`
                let ret = self.node.value.take();
                self.unsplit();
                ret
            }
        }
    }

    fn get(&self, k: &[u8]) -> Option<&T> {
        let cut_at = Self::prefix_len(k, &self.node.substr);
        if self.node.substr.len() > cut_at {
            // Key forks from `substr` or is contained in `substr`
            None
        } else {
            if k.len() > cut_at {
                // Key continues after `substr`
                if let Some(ref children) = &self.node.children {
                    if let Some(ref child) = children[k[cut_at] as usize] {
                        child.get(&k[cut_at + 1..])
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                // Key is `substr`
                self.node.value.as_ref()
            }
        }
    }

    fn get_mut(&mut self, k: &[u8]) -> Option<&mut T> {
        let cut_at = Self::prefix_len(k, &self.node.substr);
        if self.node.substr.len() > cut_at {
            // Key forks from `substr` or is contained in `substr`
            None
        } else {
            if k.len() > cut_at {
                // Key continues after `substr`
                if let Some(ref mut children) = &mut self.node.children {
                    if let Some(ref mut child) = children[k[cut_at] as usize] {
                        self.commit = None;
                        child.get_mut(&k[cut_at + 1..])
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                // Key is `substr`
                self.commit = None;
                self.node.value.as_mut()
            }
        }
    }
    
    fn iter<'a>(&'a self) -> MerkleIterator<'a, T> {
        MerkleIterator { stack: Vec::from([(self, false)]) }
    }
    
    // find a leaf where whole path passes filter. dfs order
    fn search<F>(&self, filter: F) -> Option<Vec<u8>> where
        F: Fn(&Vec<u8>, &Option<T>) -> bool
    {
        let mut prefix = Vec::new();
        match self.search_rec(&filter, &mut prefix) {
            Ok(()) => Some(prefix),
            Err(()) => None
        }
    }

    fn search_rec<'a, F>(&self, filter: &F, prefix: &'a mut Vec<u8>) -> Result<(),()> where 
        F: Fn(&Vec<u8>, &Option<T>) -> bool
    {
        prefix.extend_from_slice(&self.node.substr);
        if filter(&prefix, &self.node.value) {
            if let None = self.node.children {
                return Ok(());
            } else {
                if let Some(ref children) = self.node.children {
                    for i in 0u8..16 {
                        if let Some(ref child) = children[i as usize] {
                            prefix.push(i);
                            if let Ok(()) = child.search_rec(filter, prefix) {
                                return Ok(());
                            }
                            prefix.pop();
                        }
                    }
                }
            }
        }
        prefix.truncate(prefix.len() - self.node.substr.len());
        Err(())
    }

    fn commit(&mut self) -> [u8; 32] {
        // i hope these updates are collision resistant
        if let Some(c) = self.commit {
            c
        } else {
            let mut hasher = Sha256::new();
            hasher.update(&self.node.substr);
            if let Some(ref v) = self.node.value {
                hasher.update(serde_json::to_string(v).expect("can't serialize value"));
            }
            let mut count: u8 = 0;
            if let Some(ref mut children) = &mut self.node.children {
                for i in 0u8..16 {
                    if let Some(ref mut child) = children[i as usize] {
                        count += 1;
                        hasher.update(&[i]);
                        hasher.update(child.commit());
                    }
                }
            }
            hasher.update((self.node.substr.len() as u32).to_be_bytes());
            hasher.update(&[count]);
            let c = hasher.finalize().into();
            self.commit = Some(c);
            c
        }
    }
}

#[derive(Debug, Clone)]
pub struct MerkleIterator<'a, T> {
    stack: Vec<(&'a MerkleNode<T>, bool)>
}

impl<'a, T> MerkleIterator<'a, T> {
    // Push stuff until last vec entry has no children.
    fn advance(&mut self) {
        while let Some((ref merk, ref explored)) = self.stack.pop() {
            self.stack.push((merk, true));
            if *explored { return; }
            if let Some(ref children) = merk.node.children {
                for child in children.iter().rev().filter_map(|c| c.as_ref()) {
                    self.stack.push((child, false));
                }
            }
        }
    }
}

impl<'a, T> Iterator for MerkleIterator<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        let mut val = None;
        while val.is_none() {
            self.advance();
            val = match &self.stack.pop() {
                Some((ref merk, _)) => merk.node.value.as_ref(),
                None => return None,
            }
        }
        val
    }
}

#[derive(Debug, Clone)]
pub struct MerkleMap<D, V> {
    root: MerkleNode<V>,
    phantom: PhantomData<D>
}

impl<D, V> Default for MerkleMap<D, V> {
    fn default() -> Self {
        MerkleMap {
            root: MerkleNode::default(),
            phantom: PhantomData::default()
        }
    }
}

impl<D: Digest, V: Serialize> MerkleMap<D, V> {
    fn to_digest(k: &[u8]) -> Vec<u8> {
        let d = D::digest(k);
        let mut extended = Vec::with_capacity(2 * d.len());
        for byte in d {
            extended.push(byte >> 4);
            extended.push(byte & 0x0f);
        }
        extended
    }

    pub fn insert(&mut self, k: &[u8], v: V) -> Option<V> {
        self.root.insert(&Self::to_digest(k), v)
    }

    pub fn remove(&mut self, k: &[u8]) -> Option<V> {
        self.root.remove(&Self::to_digest(k))
    }

    pub fn get(&self, k: &[u8]) -> Option<&V> {
        self.root.get(&Self::to_digest(k))
    }

    pub fn get_mut(&mut self, k: &[u8]) -> Option<&mut V> {
        self.root.get_mut(&Self::to_digest(k))
    }

    pub fn iter<'a>(&'a self) -> MerkleIterator<'a, V> {
        self.root.iter()
    }

    pub fn search<F>(&self, filter: F) -> Option<Vec<u8>> where
        F: Fn(&Vec<u8>, &Option<V>) -> bool
    {
        self.root.search(filter)
    }

    pub fn commit(&mut self) -> [u8; 32] {
        self.root.commit()
    }
}

/*
#[derive(Debug, Clone)]
pub struct MerkleVec<V> {
    root: MerkleNode<V>,
}

impl<V> Default for MerkleVec<V> {
    fn default() -> Self {
        MerkleVec {
            root: MerkleNode::default()
        }
    }
}

impl<V: Serialize> MerkleVec<V> {
    pub fn insert(&mut self, k: &[u8], v: V) -> Option<V> {
        self.root.insert(k, v)
    }

    pub fn remove(&mut self, k: &[u8]) -> Option<V> {
        self.root.remove(k)
    }

    pub fn get(&self, k: &[u8]) -> Option<&V> {
        self.root.get(k)
    }

    pub fn get_mut(&mut self, k: &[u8]) -> Option<&mut V> {
        self.root.get_mut(k)
    }

    pub fn iter<'a>(&'a self) -> MerkleIterator<'a, V> {
        self.root.iter()
    }

    pub fn search<F>(&self, filter: F) -> Option<Vec<u8>> where
        F: Fn(&Vec<u8>, &Option<V>) -> bool
    {
        self.root.search(filter)
    }

    pub fn commit(&mut self) -> [u8; 32] {
        self.root.commit()
    }
}
*/

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_node() {
        println!("{:?}", 0u32.to_be_bytes());
        let mut node: MerkleNode<u8> = MerkleNode::default();
        assert_eq!(node.insert(&[0, 1, 2, 3], 0), None);
        // Key contained in parent path
        assert_eq!(node.insert(&[0, 1, 2], 1), None);
        assert_eq!(node.insert(&[0], 2), None);
        // Key hits a child
        assert_eq!(node.insert(&[0, 1, 2, 3, 4], 3), None);
        assert_eq!(node.insert(&[0, 4], 4), None);
        assert_eq!(node.insert(&[5], 5), None);
        // Key goes past parent path
        assert_eq!(node.insert(&[0, 1, 2, 3, 4, 5], 6), None);
        assert_eq!(node.insert(&[5, 6, 7, 8, 9], 7), None);
        // Key forks off parent path
        assert_eq!(node.insert(&[0, 1, 2, 3, 4, 6], 8), None);
        assert_eq!(node.insert(&[5, 6, 7, 5, 6], 9), None);
        // Key is existing node
        assert_eq!(node.insert(&[], 1), None);
        assert_eq!(node.insert(&[0, 1, 2], 2), Some(1));
        assert_eq!(node.insert(&[0, 1, 2, 3, 4, 5], 3), Some(6));
        assert_eq!(node.insert(&[5, 6, 7, 5, 6], 4), Some(9));
        assert_eq!(node.insert(&[5, 6, 7], 5), None);
        // Updates work
        assert_eq!(node.insert(&[], 0), Some(1));
        assert_eq!(node.insert(&[0, 1, 2], 0), Some(2));
        assert_eq!(node.insert(&[5, 6, 7], 0), Some(5));
    }

    #[test]
    fn get_node() {
        let mut node: MerkleNode<u8> = MerkleNode::default();
        node.insert(&[0, 1, 0], 0);
        node.insert(&[0, 1, 2, 3, 4], 1);
        node.insert(&[1], 2);
        node.insert(&[0, 2], 3);
        node.insert(&[0, 3, 4], 4);
        // Key contained in parent path
        assert_eq!(node.get(&[0, 1, 2, 3]), None);
        assert_eq!(node.get(&[0, 3]), None);
        // Key hits a child
        assert_eq!(node.get(&[0, 1, 2, 3, 4, 5]), None);
        assert_eq!(node.get(&[2]), None);
        // Key goes past parent path
        assert_eq!(node.get(&[0, 1, 2, 3, 4, 5, 6]), None);
        assert_eq!(node.get(&[1, 2, 3]), None);
        // Key forks off parent path
        assert_eq!(node.get(&[0, 1, 2, 1, 2]), None);
        assert_eq!(node.get(&[0, 3, 5]), None);
        // Key is existing node
        assert_eq!(node.get(&[]), None);
        assert_eq!(node.get(&[0, 1]), None);
        assert_eq!(node.get(&[0, 1, 2, 3, 4]), Some(&1));
        assert_eq!(node.get(&[1]), Some(&2));
        assert_eq!(node.get(&[0, 3, 4]), Some(&4));
        // Get mut is the same
        assert_eq!(node.get_mut(&[0, 1, 2, 3]), None);
        assert_eq!(node.get_mut(&[1, 2, 3]), None);
        assert_eq!(node.get_mut(&[0, 3, 5]), None);
        assert_eq!(node.get_mut(&[0, 3, 4]), Some(&mut 4));
        // Using get mut sets commit to none
        assert_eq!(node.commit, None);
    }

    #[test]
    fn remove_node() {
        let mut node: MerkleNode<u8> = MerkleNode::default();
        node.insert(&[], 0);
        node.insert(&[0, 1, 2, 3, 4], 1);
        node.insert(&[0, 1, 2, 5, 6, 7], 2);
        node.insert(&[0, 2, 4], 3);
        node.insert(&[0, 2, 3, 4], 4);
        // Key contained in parent path
        assert_eq!(node.remove(&[0, 1, 2, 3]), None);
        assert_eq!(node.remove(&[0, 2, 3]), None);
        // Key hits a child
        assert_eq!(node.remove(&[0, 1, 2, 3, 4, 5]), None);
        assert_eq!(node.remove(&[1]), None);
        // Key goes past parent path
        assert_eq!(node.remove(&[0, 1, 2, 5, 6, 7, 8]), None);
        assert_eq!(node.remove(&[1, 2]), None);
        // Key forks off parent path
        assert_eq!(node.remove(&[0, 1, 2, 3, 5]), None);
        assert_eq!(node.remove(&[0, 1, 2, 5, 6, 8, 9]), None);
        // Key is existing node
        assert_eq!(node.remove(&[]), Some(0));
        assert_eq!(node.remove(&[0, 2, 4]), Some(3));
        assert_eq!(node.remove(&[0, 2]), None);
    }

    #[test]
    fn commit_node() {
        let mut node: MerkleNode<u8> = MerkleNode::default();
        let mut commits1 = [[0u8; 32]; 7];
        commits1[0] = node.commit();
        node.insert(&[], 0);
        commits1[1] = node.commit();
        node.insert(&[0, 1, 2, 3], 1);
        commits1[2] = node.commit();
        node.insert(&[0, 1, 2, 3, 4, 5], 2);
        commits1[3] = node.commit();
        node.insert(&[1, 2, 3, 4, 5], 3);
        println!("{:#?}", node);
        commits1[4] = node.commit();
        node.insert(&[1, 2, 3, 4, 6], 4);
        commits1[5] = node.commit();
        node.insert(&[2], 5);
        commits1[6] = node.commit();

        let mut commits2 = [[0u8; 32]; 7];
        commits2[6] = node.commit();
        node.remove(&[2]);
        commits2[5] = node.commit();
        node.remove(&[1, 2, 3, 4, 6]);
        println!("{:#?}", node);
        commits2[4] = node.commit();
        node.remove(&[1, 2, 3, 4, 5]);
        commits2[3] = node.commit();
        node.remove(&[0, 1, 2, 3, 4, 5]);
        commits2[2] = node.commit();
        node.remove(&[0, 1, 2, 3]);
        commits2[1] = node.commit();
        node.remove(&[]);
        commits2[0] = node.commit();

        assert_eq!(commits1, commits2);
        for i in 0..7 {
            for j in 0..i {
                assert_ne!(commits1[i], commits1[j]);
            }
        }
    }

    #[test]
    fn iter_node() {
        let mut node: MerkleNode<u8> = MerkleNode::default();
        node.insert(&[], 0);
        node.insert(&[0, 1, 2, 3], 1);
        node.insert(&[0, 1, 2, 3, 4, 5], 2);
        node.insert(&[1, 2, 3, 4, 5], 3);
        node.insert(&[1, 2, 3, 4, 6], 4);
        node.insert(&[2], 5);
        let vals: Vec<&u8> = node.iter().collect();
        assert_eq!(vals, Vec::from([&2, &1, &3, &4, &5, &0]));
    }

    #[test]
    fn search_node() {
        let mut node: MerkleNode<u8> = MerkleNode::default();
        node.insert(&[0, 1, 0], 0);
        node.insert(&[0, 1, 2, 3, 4], 1);
        node.insert(&[1], 2);
        node.insert(&[0, 2], 3);
        node.insert(&[0, 3, 4], 4);
        assert_eq!(node.search(|_, opt_v| opt_v.is_none()), None);
        assert_eq!(node.search(|_, _| true), Some(Vec::from([0, 1, 0])));
        assert_eq!(node.search(|k, _| k.len() < 2), Some(Vec::from([1])));
        assert_eq!(node.search(|k, _| k.len() > 0), None);
        assert_eq!(node.search(|k, _| k.iter().fold(0, |x, y| x + y) % 2 == 0), Some(Vec::from([0, 2])));
    }
}
