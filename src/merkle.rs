use sha2::{Sha256, Digest};
use core::array;
use serde::Serialize;
use std::fmt::Debug;
use std::rc::Rc;

#[derive(Debug, Clone, Default)]
struct TrieNode<T> {
    substr: Vec<u8>,
    value: Option<T>,
    children: Option<[Option<Rc<MerkleNode<T>>>; 16]>
}

#[derive(Debug, Clone)]
pub struct MerkleNode<T> {
    node: TrieNode<T>,
    commit: [u8; 32]
}

impl<T: Serialize + Clone> MerkleNode<T> {
    fn empty_children_array() -> [Option<Rc<MerkleNode<T>>>; 16] {
        array::from_fn(|_| None)
    }

    fn new(substr: Vec<u8>, value: Option<T>, children: Option<[Option<Rc<MerkleNode<T>>>; 16]>) -> Self {
        let mut m = MerkleNode {
            node: TrieNode {
                substr,
                value,
                children
            },
            commit: [0u8; 32]
        };
        m.commit = m.commit();
        m
    }
}

impl<T: Serialize + Clone> Default for MerkleNode<T> {
    fn default() -> Self {
        Self::new(Vec::default(), None, None)
    }
}

impl<T: Serialize + Clone> MerkleNode<T> {
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
    fn split(&self, cut_at: usize) -> Self {
        let mut clone = self.clone();
        if cut_at < clone.node.substr.len() {
            let suffix = clone.node.substr.split_off(cut_at + 1);
            let mut children = Self::empty_children_array();
            children[self.node.substr[cut_at] as usize] = Some(Rc::new(Self::new(
                suffix, 
                clone.node.value.take(),
                clone.node.children.take()
            )));
            clone.node.value = None;
            clone.node.children = Some(children);
            clone.node.substr.truncate(cut_at);
        } else { 
            clone.node.children.get_or_insert(Self::empty_children_array());
        }
        clone.commit = clone.commit();
        clone
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
                    self.node.children = child.node.children.clone();
                    self.node.value = child.node.value.clone();
                } else {
                    self.node.children = Some(children);
                }
            }
        }
        self.commit = self.commit();
    }

    pub fn insert(&self, k: &[u8], v: T) -> (Self, Option<T>) {
        let cut_at = Self::prefix_len(&k, &self.node.substr);
        let mut clone = self.split(cut_at);
        if k.len() > cut_at {
            // Key forks from `substr` or key continues after `substr`
            let suffix = &k[cut_at + 1..];
            let nibble = k[cut_at] as usize;
            if let Some(ref child) = clone.node.children.as_ref().unwrap()[nibble] {
                let (child_clone, opt_val) = child.insert(suffix, v);
                clone.node.children.as_mut().unwrap()[nibble] = Some(Rc::new(child_clone));
                clone.commit = clone.commit();
                (clone, opt_val)
            } else {
                clone.node.children.as_mut().unwrap()[nibble] = Some(Rc::new(Self::new(
                    suffix.to_vec(), 
                    Some(v),
                    None
                )));
                clone.commit = clone.commit();
                (clone, None)
            }
        } else {
            if self.node.substr.len() > cut_at {
                // Key contained in `substr`
                clone.node.value = Some(v);
                (clone, None)
            } else {
                // Key is `substr`
                let opt_val = clone.node.value.replace(v);
                clone.commit = clone.commit();
                (clone, opt_val)
            }
        }
    }

    fn commit(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.node.substr);
        if let Some(ref v) = self.node.value {
            hasher.update(serde_json::to_string(v).expect("can't serialize value"));
        }
        let mut count: u8 = 0;
        if let Some(ref children) = &self.node.children {
            for i in 0u8..16 {
                if let Some(ref child) = children[i as usize] {
                    count += 1;
                    hasher.update(&[i]);
                    hasher.update(child.commit);
                }
            }
        }
        hasher.update((self.node.substr.len() as u32).to_be_bytes());
        hasher.update(&[count]);
        hasher.finalize().into()
    }

    fn remove(&self, k: &[u8]) -> (Self, Option<T>) {
        let cut_at = Self::prefix_len(&k, &self.node.substr);
        if k.len() > cut_at { 
            if self.node.substr.len() > cut_at {
                // Key forks from `substr`
                (self.clone(), None)
            } else {
                // Key continues after `substr`
                if let Some(ref children) = self.node.children.as_ref() {
                    let suffix = &k[cut_at + 1..];
                    let nibble = k[cut_at] as usize;
                    if let Some(ref child) = children[nibble] {
                        let mut clone = self.clone();
                        let (mut child_clone, ret) = child.remove(suffix);
                        if let (None, None) = (&child_clone.node.children, &child_clone.node.value) {
                            // child is empty, remove it
                            clone.node.children.as_mut().unwrap()[nibble] = None;
                        } else {
                            clone.node.children.as_mut().unwrap()[nibble] = Some(Rc::new(child_clone));
                        }
                        if clone.node.children.as_ref().unwrap().iter().filter(|g| g.is_some()).next().is_none() {
                            // children is empty, make it none.
                            clone.node.children = None;
                        }
                        clone.unsplit();
                        clone.commit = clone.commit();
                        (clone, ret)
                    } else {
                        (self.clone(), None)
                    }
                } else {
                    (self.clone(), None)
                }
            }
        } else {
            if self.node.substr.len() > cut_at {
                // Key contained in `substr`
                (self.clone(), None)
            } else {
                // Key is `substr`
                let mut clone = self.clone();
                let ret = clone.node.value.take();
                clone.unsplit();
                (clone, ret)
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
pub struct MerkleMap<V> {
    root: MerkleNode<V>
}

impl<V: Serialize + Clone> Default for MerkleMap<V> {
    fn default() -> Self {
        MerkleMap {
            root: MerkleNode::default()
        }
    }
}

impl<V: Serialize + Clone> MerkleMap<V> {
    fn to_digest(k: &[u8]) -> Vec<u8> {
        let mut extended = Vec::with_capacity(2 * k.len());
        for byte in k {
            extended.push(byte >> 4);
            extended.push(byte & 0x0f);
        }
        extended
    }

    pub fn insert(&mut self, k: &[u8], v: V) -> Option<V> {
        let mut opt_val = None;
        (self.root, opt_val) = self.root.insert(&Self::to_digest(k), v);
        opt_val
    }

    pub fn remove(&mut self, k: &[u8]) -> Option<V> {
        let mut opt_val = None;
        (self.root, opt_val) = self.root.remove(&Self::to_digest(k));
        opt_val
    }

    pub fn get(&self, k: &[u8]) -> Option<&V> {
        self.root.get(&Self::to_digest(k))
    }

    pub fn iter<'a>(&'a self) -> MerkleIterator<'a, V> {
        self.root.iter()
    }

    pub fn search<F>(&self, filter: F) -> Option<Vec<u8>> where
        F: Fn(&Vec<u8>, &Option<V>) -> bool
    {
        self.root.search(filter)
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_node() {
        println!("{:?}", 0u32.to_be_bytes());
        let mut node: MerkleNode<u8> = MerkleNode::default();
        let mut opt_val = None;
        (node, opt_val) = node.insert(&[0, 1, 2, 3], 0);
        assert_eq!(opt_val, None);
        // Key contained in parent path
        (node, opt_val) =node.insert(&[0, 1, 2], 1);
        assert_eq!(opt_val, None);
        (node, opt_val) = node.insert(&[0], 2);
        assert_eq!(opt_val, None);
        // Key hits a child
        (node, opt_val) = node.insert(&[0, 1, 2, 3, 4], 3);
        assert_eq!(opt_val, None);
        (node, opt_val) = node.insert(&[0, 4], 4);
        assert_eq!(opt_val, None);
        (node, opt_val) = node.insert(&[5], 5);
        assert_eq!(opt_val, None);
        // Key goes past parent path
        (node, opt_val) = node.insert(&[0, 1, 2, 3, 4, 5], 6);
        assert_eq!(opt_val, None);
        (node, opt_val) = node.insert(&[5, 6, 7, 8, 9], 7);
        assert_eq!(opt_val, None);
        // Key forks off parent path
        (node, opt_val) = node.insert(&[0, 1, 2, 3, 4, 6], 8);
        assert_eq!(opt_val, None);
        (node, opt_val) = node.insert(&[5, 6, 7, 5, 6], 9);
        assert_eq!(opt_val, None);
        // Key is existing node
        (node, opt_val) = node.insert(&[], 1);
        assert_eq!(opt_val, None);
        (node, opt_val) = node.insert(&[0, 1, 2], 2);
        assert_eq!(opt_val, Some(1));
        (node, opt_val) = node.insert(&[0, 1, 2, 3, 4, 5], 3);
        assert_eq!(opt_val, Some(6));
        (node, opt_val) = node.insert(&[5, 6, 7, 5, 6], 4);
        assert_eq!(opt_val, Some(9));
        (node, opt_val) = node.insert(&[5, 6, 7], 5);
        assert_eq!(opt_val, None);
        // Updates work
        (node, opt_val) = node.insert(&[], 0);
        assert_eq!(opt_val, Some(1));
        (node, opt_val) = node.insert(&[0, 1, 2], 0);
        assert_eq!(opt_val, Some(2));
        (node, opt_val) = node.insert(&[5, 6, 7], 0);
        assert_eq!(opt_val, Some(5));
    }

    #[test]
    fn get_node() {
        let mut node = MerkleNode::default()
            .insert(&[0, 1, 0], 0).0
            .insert(&[0, 1, 2, 3, 4], 1).0
            .insert(&[1], 2).0
            .insert(&[0, 2], 3).0
            .insert(&[0, 3, 4], 4).0;
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

    }

    #[test]
    fn remove_node() {
        let mut node: MerkleNode<u8> = MerkleNode::default()
            .insert(&[], 0).0
            .insert(&[0, 1, 2, 3, 4], 1).0
            .insert(&[0, 1, 2, 5, 6, 7], 2).0
            .insert(&[0, 2, 4], 3).0
            .insert(&[0, 2, 3, 4], 4).0;
        let mut opt_val = None;
        // Key contained in parent path
        (node, opt_val) = node.remove(&[0, 1, 2, 3]);
        assert_eq!(opt_val, None);
        (node, opt_val) = node.remove(&[0, 2, 3]);
        assert_eq!(opt_val, None);
        // Key hits a child
        (node, opt_val) = node.remove(&[0, 1, 2, 3, 4, 5]);
        assert_eq!(opt_val, None);
        (node, opt_val) = node.remove(&[1]);
        assert_eq!(opt_val, None);
        // Key goes past parent path
        (node, opt_val) = node.remove(&[0, 1, 2, 5, 6, 7, 8]);
        assert_eq!(opt_val, None);
        (node, opt_val) = node.remove(&[1, 2]);
        assert_eq!(opt_val, None);
        // Key forks off parent path
        (node, opt_val) = node.remove(&[0, 1, 2, 3, 5]);
        assert_eq!(opt_val, None);
        (node, opt_val) = node.remove(&[0, 1, 2, 5, 6, 8, 9]);
        assert_eq!(opt_val, None);
        // Key is existing node
        (node, opt_val) = node.remove(&[]);
        assert_eq!(opt_val, Some(0));
        (node, opt_val) = node.remove(&[0, 2, 4]);
        assert_eq!(opt_val, Some(3));
        (node, opt_val) = node.remove(&[0, 2]);
        assert_eq!(opt_val, None);
    }

    #[test]
    fn commit_node() {
        let mut node: MerkleNode<u8> = MerkleNode::default();
        let mut commits1 = [[0u8; 32]; 7];
        commits1[0] = node.commit;
        node = node.insert(&[], 0).0;
        commits1[1] = node.commit;
        node = node.insert(&[0, 1, 2, 3], 1).0;
        commits1[2] = node.commit;
        node = node.insert(&[0, 1, 2, 3, 4, 5], 2).0;
        println!("{:?}", node.get(&[0, 1, 2, 3, 4, 5]));
        commits1[3] = node.commit;
        node = node.insert(&[1, 2, 3, 4, 5], 3).0;
        commits1[4] = node.commit;
        node = node.insert(&[1, 2, 3, 4, 6], 4).0;
        commits1[5] = node.commit;
        node = node.insert(&[2], 5).0;
        commits1[6] = node.commit;

        let mut commits2 = [[0u8; 32]; 7];
        commits2[6] = node.commit;
        node = node.remove(&[2]).0;
        commits2[5] = node.commit;
        node = node.remove(&[1, 2, 3, 4, 6]).0;
        commits2[4] = node.commit;
        node = node.remove(&[1, 2, 3, 4, 5]).0;
        commits2[3] = node.commit;
        node = node.remove(&[0, 1, 2, 3, 4, 5]).0;
        commits2[2] = node.commit;
        node = node.remove(&[0, 1, 2, 3]).0;
        commits2[1] = node.commit;
        node = node.remove(&[]).0;
        commits2[0] = node.commit;

        assert_eq!(commits1, commits2);
        for i in 0..7 {
            println!("{:?}", commits1[i]);
            println!("{:?}", commits2[i]);
            for j in 0..i {
                assert_ne!(commits1[i], commits1[j]);
            }
        }
    }

    #[test]
    fn iter_node() {
        let mut node: MerkleNode<u8> = MerkleNode::default()
            .insert(&[], 0).0
            .insert(&[0, 1, 2, 3], 1).0
            .insert(&[0, 1, 2, 3, 4, 5], 2).0
            .insert(&[1, 2, 3, 4, 5], 3).0
            .insert(&[1, 2, 3, 4, 6], 4).0
            .insert(&[2], 5).0;
        let vals: Vec<&u8> = node.iter().collect();
        assert_eq!(vals, Vec::from([&2, &1, &3, &4, &5, &0]));
    }

    #[test]
    fn search_node() {
        let mut node: MerkleNode<u8> = MerkleNode::default()
            .insert(&[0, 1, 0], 0).0
            .insert(&[0, 1, 2, 3, 4], 1).0
            .insert(&[1], 2).0
            .insert(&[0, 2], 3).0
            .insert(&[0, 3, 4], 4).0;
        assert_eq!(node.search(|_, opt_v| opt_v.is_none()), None);
        assert_eq!(node.search(|_, _| true), Some(Vec::from([0, 1, 0])));
        assert_eq!(node.search(|k, _| k.len() < 2), Some(Vec::from([1])));
        assert_eq!(node.search(|k, _| k.len() > 0), None);
        assert_eq!(node.search(|k, _| k.iter().fold(0, |x, y| x + y) % 2 == 0), Some(Vec::from([0, 2])));
    }
    
}
