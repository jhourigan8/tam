use sha2::{Sha256, Digest};
use core::array;
use serde::{Serialize, Deserialize};
use std::fmt::Debug;
use std::sync::Arc;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct TrieNode<T> {
    substr: Vec<u8>,
    value: Option<T>,
    children: Option<[Option<Arc<Node<T>>>; 16]>
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Node<T> {
    node: Option<TrieNode<T>>, // None for serialize and send
    commit: [u8; 32]
}

impl<T: Serialize + Clone> Node<T> {
    fn empty_children_array() -> [Option<Arc<Node<T>>>; 16] {
        array::from_fn(|_| None)
    }

    fn new(substr: Vec<u8>, value: Option<T>, children: Option<[Option<Arc<Node<T>>>; 16]>) -> Self {
        let mut m = Node {
            node: Some( TrieNode {
                substr,
                value,
                children
            }),
            commit: [0u8; 32]
        };
        m.commit = m.commit();
        m
    }
}

impl<T: Serialize + Clone> Default for Node<T> {
    fn default() -> Self {
        Self::new(Vec::default(), None, None)
    }
}

impl<T: Serialize + Clone> Node<T> {
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
    fn split(&self, cut_at: usize) -> Result<Self, ()> {
        let mut clone = self.clone();
        let mut node = clone.node.as_mut().ok_or(())?;
        if cut_at < node.substr.len() {
            let suffix = node.substr.split_off(cut_at + 1);
            let mut children = Self::empty_children_array();
            children[node.substr[cut_at] as usize] = Some(Arc::new(Self::new(
                suffix, 
                node.value.take(),
                node.children.take()
            )));
            node.value = None;
            node.children = Some(children);
            node.substr.truncate(cut_at);
        } else { 
            node.children.get_or_insert(Self::empty_children_array());
        }
        clone.commit = clone.commit();
        Ok(clone)
    }

    // If I only have one child and no value absorb it into me.
    // Otherwise do nothing.
    fn unsplit(&mut self) -> Result<(), ()> {
        let mut node = self.node.as_mut().ok_or(())?;
        if node.value.is_none() {
            if let Some(mut children) = node.children.take() {
                let mut some_iter = children.iter_mut().enumerate().filter_map(|(i, opt_g)| opt_g.as_mut().map(|g| (i, g)));
                let opt_child = some_iter.next();
                if let (Some((i, child)), None) = (opt_child, some_iter.next()) {
                    node.substr.push(i as u8);
                    let child_node = child.node.as_ref().ok_or(())?;
                    node.substr.extend_from_slice(&child_node.substr);
                    node.children = child_node.children.clone();
                    node.value = child_node.value.clone();
                } else {
                    node.children = Some(children);
                }
            }
        }
        self.commit = self.commit();
        Ok(())
    }

    pub fn insert(&self, k: &[u8], v: T) -> Result<(Self, Option<T>), ()> {
        let node = self.node.as_ref().ok_or(())?;
        let cut_at = Self::prefix_len(&k, &node.substr);
        let mut clone = self.split(cut_at)?;
        let clone_node = clone.node.as_mut().unwrap();
        if k.len() > cut_at {
            // Key forks from `substr` or key continues after `substr`
            let suffix = &k[cut_at + 1..];
            let nibble = k[cut_at] as usize;
            if let Some(ref child) = clone_node.children.as_ref().unwrap()[nibble] {
                let (child_clone, opt_val) = child.insert(suffix, v)?;
                clone_node.children.as_mut().unwrap()[nibble] = Some(Arc::new(child_clone));
                clone.commit = clone.commit();
                Ok((clone, opt_val))
            } else {
                clone_node.children.as_mut().unwrap()[nibble] = Some(Arc::new(Self::new(
                    suffix.to_vec(), 
                    Some(v),
                    None
                )));
                clone.commit = clone.commit();
                Ok((clone, None))
            }
        } else {
            if node.substr.len() > cut_at {
                // Key contained in `substr`
                clone_node.value = Some(v);
                clone.commit = clone.commit();
                Ok((clone, None))
            } else {
                // Key is `substr`
                let opt_val = clone_node.value.replace(v);
                clone.commit = clone.commit();
                Ok((clone, opt_val))
            }
        }
    }

    fn commit(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        let node = self.node.as_ref().unwrap();
        hasher.update(&node.substr);
        if let Some(ref v) = node.value {
            hasher.update(serde_json::to_string(v).expect("can't serialize value"));
        }
        let mut count: u8 = 0;
        if let Some(ref children) = &node.children {
            for i in 0u8..16 {
                if let Some(ref child) = children[i as usize] {
                    count += 1;
                    hasher.update(&[i]);
                    hasher.update(child.commit);
                }
            }
        }
        hasher.update((node.substr.len() as u32).to_be_bytes());
        hasher.update(&[count]);
        hasher.finalize().into()
    }

    fn remove(&self, k: &[u8]) -> Result<(Self, Option<T>), ()> {
        let node = self.node.as_ref().ok_or(())?;
        let cut_at = Self::prefix_len(&k, &node.substr);
        if k.len() > cut_at { 
            if node.substr.len() > cut_at {
                // Key forks from `substr`
                Ok((self.clone(), None))
            } else {
                // Key continues after `substr`
                if let Some(ref children) = node.children.as_ref() {
                    let suffix = &k[cut_at + 1..];
                    let nibble = k[cut_at] as usize;
                    if let Some(ref child) = children[nibble] {
                        let mut clone = self.clone();
                        let mut clone_node = clone.node.as_mut().ok_or(())?;
                        let (child_clone, ret) = child.remove(suffix)?;
                        let child_clone_node = child_clone.node.as_ref().ok_or(())?;
                        if let (None, None) = (&child_clone_node.children, &child_clone_node.value) {
                            // child is empty, remove it
                            clone_node.children.as_mut().unwrap()[nibble] = None;
                        } else {
                            clone_node.children.as_mut().unwrap()[nibble] = Some(Arc::new(child_clone));
                        }
                        if clone_node.children.as_ref().unwrap().iter().filter(|g| g.is_some()).next().is_none() {
                            // children is empty, make it none.
                            clone_node.children = None;
                        }
                        clone.unsplit()?;
                        clone.commit = clone.commit();
                        Ok((clone, ret))
                    } else {
                        Ok((self.clone(), None))
                    }
                } else {
                    Ok((self.clone(), None))
                }
            }
        } else {
            if node.substr.len() > cut_at {
                // Key contained in `substr`
                Ok((self.clone(), None))
            } else {
                // Key is `substr`
                let mut clone = self.clone();
                let clone_node = clone.node.as_mut().ok_or(())?;
                let ret = clone_node.value.take();
                clone.unsplit()?;
                Ok((clone, ret))
            }
        }
    }

    fn get(&self, k: &[u8]) -> Result<Option<&T>, ()> {
        let node = self.node.as_ref().ok_or(())?;
        let cut_at = Self::prefix_len(k, &node.substr);
        if node.substr.len() > cut_at {
            // Key forks from `substr` or is contained in `substr`
            Ok(None)
        } else {
            if k.len() > cut_at {
                // Key continues after `substr`
                if let Some(ref children) = &node.children {
                    if let Some(ref child) = children[k[cut_at] as usize] {
                        child.get(&k[cut_at + 1..])
                    } else {
                        Ok(None)
                    }
                } else {
                    Ok(None)
                }
            } else {
                // Key is `substr`
                Ok(node.value.as_ref())
            }
        }
    }

    /*
    fn path(&self, k: &[u8]) -> Vec<&Self> {
        let cut_at = Self::prefix_len(k, &self.node.substr);
        if self.node.substr.len() > cut_at {
            // Key forks from `substr` or is contained in `substr`
            Vec::from([self])
        } else {
            if k.len() > cut_at {
                // Key continues after `substr`
                if let Some(ref children) = &self.node.children {
                    if let Some(ref child) = children[k[cut_at] as usize] {
                        let mut v = child.path(&k[cut_at + 1..]);
                        v.push(self);
                        v
                    } else {
                        Vec::from([self])
                    }
                } else {
                    Vec::from([self])
                }
            } else {
                // Key is `substr`
                Vec::from([self])
            }
        }
    }
    */

    fn iter<'a>(&'a self) -> MerkleIterator<'a, T> {
        MerkleIterator { stack: Vec::from([(self, false)]) }
    }

    /*
    // Get subtrie only containing data at ks
    // If true, include its entire subtree, else don't
    // Assumes have all state
    fn subtrie(&self, ks: Vec<(&[u8], bool)>) -> Option<Self> {
        let mut recs: [Vec<(&[u8], bool)>; 16] = array::from_fn(|_| Vec::default());
        let mut include_self = false;
        let mut include_kids = false;
        let mut clone = self.clone();
        for (k, kids) in ks {
            let cut_at = Self::prefix_len(k, &self.node.as_ref().unwrap().substr);
            if k.len() == cut_at {
                include_self = true;
                include_kids |= kids;
            } else if k.len() > cut_at {
                recs[k[cut_at] as usize].push((&k[cut_at + 1..], kids));
            }
        }
        if include_kids {
            return Some(clone);
        }
        let mut include_any = include_self;
        if let Some(ref mut children) = clone.node.as_mut().unwrap().children {
            for (opt_child, rec) in children.iter_mut().zip(recs.into_iter()) {
                if rec.is_empty() {
                    *opt_child = None;
                } else {
                    include_any = true;
                    if let Some(child) = opt_child {
                        *opt_child = child.subtrie(rec).map(|s| Arc::new(s));
                    }
                }
            }
        }
        if include_any {
            Some(clone)
        } else {
            None
        }
    }
    */

    // Update this merkle trie with data from another
    pub fn update(&self, k: &[u8], mut other: Node<T>) -> Result<Self, ()> {
        let node = self.node.as_ref().ok_or(())?;
        let cut_at = Self::prefix_len(k, &node.substr);
        let mut clone = self.clone();
        if node.substr.len() > cut_at {
            // Key forks from `substr` or is contained in `substr`
            Err(())
        } else {
            if k.len() > cut_at {
                // Key continues after `substr`
                if let Some(ref children) = &node.children {
                    if let Some(ref child) = children[k[cut_at] as usize] {
                        child.update(&k[cut_at + 1..], other)
                    } else {
                        Err(())
                    }
                } else {
                    Err(())
                }
            } else {
                // Key is `substr`
                clone.node = other.node.take();
                clone.commit = other.commit;
                Ok(clone)
            }
        }
    }

    // verify hash integrity fn
    pub fn valid_commits(&self) -> Result<(), ()> {
        if self.commit != self.commit() {
            println!("commit is {:?} should be {:?}", self.commit, self.commit());
            Err(())
        } else {
            if let Some(node) = self.node.as_ref() {
                if let Some(ref children) = node.children {
                    for opt_child in children {
                        if let Some(child) = opt_child {
                            child.valid_commits()?;
                        }
                    }
                }
            }
            Ok(())
        }
    }
    
}

#[derive(Debug, Clone)]
pub struct MerkleIterator<'a, T> {
    stack: Vec<(&'a Node<T>, bool)>
}

impl<'a, T> MerkleIterator<'a, T> {
    // Push stuff until last vec entry has no children.
    fn advance(&mut self) {
        while let Some((ref merk, ref explored)) = self.stack.pop() {
            self.stack.push((merk, true));
            if *explored { return; }
            if let Some(ref children) = merk.node.as_ref().unwrap().children {
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
                Some((ref merk, _)) => {
                    match merk.node {
                        Some(ref node) => node.value.as_ref(),
                        None => continue,
                    }
                },
                None => return None,
            }
        }
        val
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Map<V> {
    root: Node<V>
}

impl<V: Serialize + Clone> Default for Map<V> {
    fn default() -> Self {
        Map {
            root: Node::default()
        }
    }
}

impl<V: Serialize + Clone> Map<V> {
    fn to_digest(k: &[u8]) -> Vec<u8> {
        let mut extended = Vec::with_capacity(2 * k.len());
        for byte in k {
            extended.push(byte >> 4);
            extended.push(byte & 0x0f);
        }
        extended
    }

    pub fn insert(&mut self, k: &[u8], v: V) -> Result<Option<V>, ()> {
        let (root, opt_val) = self.root.insert(&Self::to_digest(k), v)?;
        self.root = root;
        Ok(opt_val)
    }

    pub fn remove(&mut self, k: &[u8]) -> Result<Option<V>, ()> {
        let (root, opt_val) = self.root.remove(&Self::to_digest(k))?;
        self.root = root;
        Ok(opt_val)
    }

    pub fn get(&self, k: &[u8]) -> Result<Option<&V>, ()> {
        self.root.get(&Self::to_digest(k))
    }

    pub fn iter<'a>(&'a self) -> MerkleIterator<'a, V> {
        self.root.iter()
    }

    pub fn commit(&self) -> [u8; 32] {
        self.root.commit
    }

    pub fn valid_commits(&self) -> Result<(), ()> {
        self.root.valid_commits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert() {
        let (mut node, mut opt_val) = Node::default().insert(&[0, 1, 2, 3], 0).unwrap();
        assert_eq!(opt_val, None);
        // Key contained in parent path
        (node, opt_val) =node.insert(&[0, 1, 2], 1).unwrap();
        assert_eq!(opt_val, None);
        (node, opt_val) = node.insert(&[0], 2).unwrap();
        assert_eq!(opt_val, None);
        // Key hits a child
        (node, opt_val) = node.insert(&[0, 1, 2, 3, 4], 3).unwrap();
        assert_eq!(opt_val, None);
        (node, opt_val) = node.insert(&[0, 4], 4).unwrap();
        assert_eq!(opt_val, None);
        (node, opt_val) = node.insert(&[5], 5).unwrap();
        assert_eq!(opt_val, None);
        // Key goes past parent path
        (node, opt_val) = node.insert(&[0, 1, 2, 3, 4, 5], 6).unwrap();
        assert_eq!(opt_val, None);
        (node, opt_val) = node.insert(&[5, 6, 7, 8, 9], 7).unwrap();
        assert_eq!(opt_val, None);
        // Key forks off parent path
        (node, opt_val) = node.insert(&[0, 1, 2, 3, 4, 6], 8).unwrap();
        assert_eq!(opt_val, None);
        (node, opt_val) = node.insert(&[5, 6, 7, 5, 6], 9).unwrap();
        assert_eq!(opt_val, None);
        // Key is existing node
        (node, opt_val) = node.insert(&[], 1).unwrap();
        assert_eq!(opt_val, None);
        (node, opt_val) = node.insert(&[0, 1, 2], 2).unwrap();
        assert_eq!(opt_val, Some(1));
        (node, opt_val) = node.insert(&[0, 1, 2, 3, 4, 5], 3).unwrap();
        assert_eq!(opt_val, Some(6));
        (node, opt_val) = node.insert(&[5, 6, 7, 5, 6], 4).unwrap();
        assert_eq!(opt_val, Some(9));
        (node, opt_val) = node.insert(&[5, 6, 7], 5).unwrap();
        assert_eq!(opt_val, None);
        // Updates work
        (node, opt_val) = node.insert(&[], 0).unwrap();
        assert_eq!(opt_val, Some(1));
        (node, opt_val) = node.insert(&[0, 1, 2], 0).unwrap();
        assert_eq!(opt_val, Some(2));
        (_, opt_val) = node.insert(&[5, 6, 7], 0).unwrap();
        assert_eq!(opt_val, Some(5));
    }

    #[test]
    fn get() {
        let node = Node::default()
            .insert(&[0, 1, 0], 0).unwrap().0
            .insert(&[0, 1, 2, 3, 4], 1).unwrap().0
            .insert(&[1], 2).unwrap().0
            .insert(&[0, 2], 3).unwrap().0
            .insert(&[0, 3, 4], 4).unwrap().0;
        // Key contained in parent path
        assert_eq!(node.get(&[0, 1, 2, 3]).unwrap(), None);
        assert_eq!(node.get(&[0, 3]).unwrap(), None);
        // Key hits a child
        assert_eq!(node.get(&[0, 1, 2, 3, 4, 5]).unwrap(), None);
        assert_eq!(node.get(&[2]).unwrap(), None);
        // Key goes past parent path
        assert_eq!(node.get(&[0, 1, 2, 3, 4, 5, 6]).unwrap(), None);
        assert_eq!(node.get(&[1, 2, 3]).unwrap(), None);
        // Key forks off parent path
        assert_eq!(node.get(&[0, 1, 2, 1, 2]).unwrap(), None);
        assert_eq!(node.get(&[0, 3, 5]).unwrap(), None);
        // Key is existing node
        assert_eq!(node.get(&[]).unwrap(), None);
        assert_eq!(node.get(&[0, 1]).unwrap(), None);
        assert_eq!(node.get(&[0, 1, 2, 3, 4]).unwrap(), Some(&1));
        assert_eq!(node.get(&[1]).unwrap(), Some(&2));
        assert_eq!(node.get(&[0, 3, 4]).unwrap(), Some(&4));

    }

    #[test]
    fn remove() {
        let node: Node<u8> = Node::default()
            .insert(&[], 0).unwrap().0
            .insert(&[0, 1, 2, 3, 4], 1).unwrap().0
            .insert(&[0, 1, 2, 5, 6, 7], 2).unwrap().0
            .insert(&[0, 2, 4], 3).unwrap().0
            .insert(&[0, 2, 3, 4], 4).unwrap().0;
        // Key contained in parent path
        let (mut node, mut opt_val) = node.remove(&[0, 1, 2, 3]).unwrap();
        assert_eq!(opt_val, None);
        (node, opt_val) = node.remove(&[0, 2, 3]).unwrap();
        assert_eq!(opt_val, None);
        // Key hits a child
        (node, opt_val) = node.remove(&[0, 1, 2, 3, 4, 5]).unwrap();
        assert_eq!(opt_val, None);
        (node, opt_val) = node.remove(&[1]).unwrap();
        assert_eq!(opt_val, None);
        // Key goes past parent path
        (node, opt_val) = node.remove(&[0, 1, 2, 5, 6, 7, 8]).unwrap();
        assert_eq!(opt_val, None);
        (node, opt_val) = node.remove(&[1, 2]).unwrap();
        assert_eq!(opt_val, None);
        // Key forks off parent path
        (node, opt_val) = node.remove(&[0, 1, 2, 3, 5]).unwrap();
        assert_eq!(opt_val, None);
        (node, opt_val) = node.remove(&[0, 1, 2, 5, 6, 8, 9]).unwrap();
        assert_eq!(opt_val, None);
        // Key is existing node
        (node, opt_val) = node.remove(&[]).unwrap();
        assert_eq!(opt_val, Some(0));
        (node, opt_val) = node.remove(&[0, 2, 4]).unwrap();
        assert_eq!(opt_val, Some(3));
        (_, opt_val) = node.remove(&[0, 2]).unwrap();
        assert_eq!(opt_val, None);
    }

    #[test]
    fn commit() {
        let mut node: Node<u8> = Node::default();
        let mut commits1 = [[0u8; 32]; 7];
        commits1[0] = node.commit;
        node = node.insert(&[], 0).unwrap().0;
        commits1[1] = node.commit;
        node = node.insert(&[0, 1, 2, 3], 1).unwrap().0;
        commits1[2] = node.commit;
        node = node.insert(&[0, 1, 2, 3, 4, 5], 2).unwrap().0;
        commits1[3] = node.commit;
        node = node.insert(&[1, 2, 3, 4, 5], 3).unwrap().0;
        commits1[4] = node.commit;
        node = node.insert(&[1, 2, 3, 4, 6], 4).unwrap().0;
        commits1[5] = node.commit;
        node = node.insert(&[2], 5).unwrap().0;
        commits1[6] = node.commit;

        let mut commits2 = [[0u8; 32]; 7];
        commits2[6] = node.commit;
        node = node.remove(&[2]).unwrap().0;
        commits2[5] = node.commit;
        node = node.remove(&[1, 2, 3, 4, 6]).unwrap().0;
        commits2[4] = node.commit;
        node = node.remove(&[1, 2, 3, 4, 5]).unwrap().0;
        commits2[3] = node.commit;
        node = node.remove(&[0, 1, 2, 3, 4, 5]).unwrap().0;
        commits2[2] = node.commit;
        node = node.remove(&[0, 1, 2, 3]).unwrap().0;
        commits2[1] = node.commit;
        node = node.remove(&[]).unwrap().0;
        commits2[0] = node.commit;

        assert_eq!(commits1, commits2);
        for i in 0..7 {
            for j in 0..i {
                assert_ne!(commits1[i], commits1[j]);
            }
        }
    }

    #[test]
    fn iter() {
        let node: Node<u8> = Node::default()
            .insert(&[], 0).unwrap().0
            .insert(&[0, 1, 2, 3], 1).unwrap().0
            .insert(&[0, 1, 2, 3, 4, 5], 2).unwrap().0
            .insert(&[1, 2, 3, 4, 5], 3).unwrap().0
            .insert(&[1, 2, 3, 4, 6], 4).unwrap().0
            .insert(&[2], 5).unwrap().0;
        let vals: Vec<&u8> = node.iter().collect();
        assert_eq!(vals, Vec::from([&2, &1, &3, &4, &5, &0]));
    }

    #[test]
    fn validcommits() {
        // Don't really test for errors but the code is pretty obviously correct for error catching?
        let mut node: Node<u8> = Node::default();
        assert_eq!(node.valid_commits(), Ok(()));
        node = node.insert(&[], 0).unwrap().0;
        assert_eq!(node.valid_commits(), Ok(()));
        node = node.insert(&[0, 1, 2, 3, 4, 5], 2).unwrap().0;
        assert_eq!(node.valid_commits(), Ok(()));
        node = node.insert(&[1, 2, 3, 4, 5], 3).unwrap().0;
        assert_eq!(node.valid_commits(), Ok(()));
        node.commit = [0u8; 32];
        assert_eq!(node.valid_commits(), Err(()));
        node = node.insert(&[1, 2, 3, 4, 6], 4).unwrap().0;
        assert_eq!(node.valid_commits(), Ok(()));
        node = node.insert(&[2], 5).unwrap().0;
        assert_eq!(node.valid_commits(), Ok(()));
    }
    
}
