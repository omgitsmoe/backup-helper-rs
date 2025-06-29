// for deterministic ordering in testing
#[cfg(test)]
pub type Map<K, V> = std::collections::BTreeMap<K, V>;

#[cfg(not(test))]
pub type Map<K, V> = std::collections::HashMap<K, V>;

#[cfg(test)]
pub type MapIter<'a, K, V> = std::collections::btree_map::Iter<'a, K, V>;

#[cfg(not(test))]
pub type MapIter<'a, K, V> = std::collections::hash_map::Iter<'a, K, V>;
