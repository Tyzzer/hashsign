use std::marker::PhantomData;
use ::utils::Hash;


#[allow(non_camel_case_types)]
#[derive(Clone, Debug)]
pub enum Tree<H> {
    Node(Vec<Tree<H>>),
    Leaf(Vec<u8>),

    #[doc(hidden)]
    __(PhantomData<H>)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TreeBin {
    Node(Vec<TreeBin>),
    Leaf(Vec<u8>)
}

impl<H: Hash> Tree<H> {
    #[inline]
    pub fn node() -> Tree<H> {
        Tree::Node(Vec::with_capacity(2))
    }

    #[inline]
    pub fn leaf(data: &[u8]) -> Tree<H> {
        Tree::Leaf(H::hash(data))
    }

    pub fn hash(&self) -> Vec<u8> {
        match *self {
            Tree::Node(ref nodes) => {
                H::hash(
                    &nodes.iter()
                        .map(|node| node.hash())
                        .fold(Vec::with_capacity(2), |mut sum, mut next| {
                            sum.append(&mut next);
                            sum
                        })
                )
            },
            Tree::Leaf(ref hash) => hash.clone(),
            _ => unreachable!()
        }
    }

    pub fn push(&mut self, tree: Tree<H>) -> &mut Tree<H> {
        match *self {
            Tree::Node(ref mut nodes) => nodes.push(tree),
            _ => unreachable!(),
        };
        self
    }
}

impl<H: Hash+Clone> Tree<H> {
    pub fn build(mut leafs: Vec<Tree<H>>) -> Tree<H> {
        if leafs.len() == 1 {
            leafs.remove(0)
        } else {
            debug_assert_eq!(leafs.len() % 2, 0);
            Tree::build(
                leafs.chunks(2)
                    .map(|leaf| Tree::Node(leaf.into()))
                    .collect()
            )
        }
    }
}

impl<H: Clone> Into<TreeBin> for Tree<H> {
    fn into(self) -> TreeBin {
        match self {
            Tree::Node(nodes) => TreeBin::Node(
                nodes.iter()
                    .cloned()
                    .map(|n| n.into())
                    .collect()
            ),
            Tree::Leaf(leaf) => TreeBin::Leaf(leaf),
            _ => unreachable!()
        }
    }
}

impl<H: Clone> From<TreeBin> for Tree<H> {
    fn from(bin: TreeBin) -> Tree<H> {
        match bin {
            TreeBin::Node(nodes) => Tree::Node(
                nodes.iter()
                    .cloned()
                    .map(|n| n.into())
                    .collect()
            ),
            TreeBin::Leaf(leaf) => Tree::Leaf(leaf)
        }
    }
}


#[test]
fn test_tree() {
    use crypto::sha2::Sha256;

    let mut root = Tree::<Sha256>::node();
    let (a, b, c, d) = (rand!(32), rand!(32), rand!(32), rand!(32));

    let node1 = Tree::Node(vec![
        Tree::leaf(&a),
        Tree::leaf(&b)
    ]);
    let node2 = Tree::Node(vec![
        Tree::leaf(&c),
        Tree::leaf(&d)
    ]);

    assert_eq!(
        root.push(node1).push(node2).hash(),
        Sha256::hash(&[
            Sha256::hash(&[
                Sha256::hash(&a),
                Sha256::hash(&b)
            ].concat()),
            Sha256::hash(&[
                Sha256::hash(&c),
                Sha256::hash(&d)
            ].concat())
        ].concat())
    );
}

#[test]
fn test_tree_build() {
    use crypto::sha2::Sha256;

    let (a, b, c, d) = (rand!(32), rand!(32), rand!(32), rand!(32));

    assert_eq!(
        Tree::<Sha256>::build(
            [&a, &b, &c, &d].iter()
                .map(|leaf| Tree::leaf(leaf))
                .collect()
        ).hash(),
        Sha256::hash(&[
            Sha256::hash(&[
                Sha256::hash(&a),
                Sha256::hash(&b)
            ].concat()),
            Sha256::hash(&[
                Sha256::hash(&c),
                Sha256::hash(&d)
            ].concat())
        ].concat())
    );
}
