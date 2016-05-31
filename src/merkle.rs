use std::marker::PhantomData;
use ::utils::Hash;


#[allow(non_camel_case_types)]
#[derive(Clone, Debug)]
pub enum Tree<H: Hash> {
    Node(Vec<Tree<H>>),
    Leaf(Vec<u8>),

    #[doc(hidden)]
    __(PhantomData<H>)
}

impl<H: Hash> Tree<H> {
    pub fn node() -> Tree<H> {
        Tree::Node(Vec::new())
    }

    pub fn leaf(data: &[u8]) -> Tree<H> {
        Tree::Leaf(H::hash(data))
    }

    pub fn hash(&self) -> Vec<u8> {
        match *self {
            Tree::Node(ref nodes) => {
                H::hash(
                    &nodes.iter()
                        .map(|node| node.hash())
                        .fold(Vec::new(), |mut sum, mut next| {
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
