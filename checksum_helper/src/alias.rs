// NOTE: unordered on purpose: the entries of a HashCollection are iterated in
//       the order of the FileTree, see `HashCollection::iter_sorted`
pub type Map<K, V> = std::collections::HashMap<K, V>;
