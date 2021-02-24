use std::iter::repeat_with;
use std::ops::{Deref, DerefMut};
use tokio::sync::RwLock;

use spectrum_primitives::prg::group::ElementVector;
use spectrum_primitives::{bytes::Bytes, group::Group};

pub trait Accumulatable {
    /// Parameters for creating an empty Accumultable.
    ///
    /// There's no one-size-fits-all à la Default, because many Accumulatables
    /// have some notion of length.
    type Parameters: Copy;
    // TODO: other should be a reference?
    fn combine(&mut self, other: Self);

    fn empty(params: Self::Parameters) -> Self;
}

impl Accumulatable for Bytes {
    type Parameters = usize;

    fn combine(&mut self, other: Bytes) {
        *self ^= &other;
    }

    fn empty(length: usize) -> Self {
        Bytes::empty(length)
    }
}

impl<G> Accumulatable for ElementVector<G>
where
    G: Group,
{
    type Parameters = usize;
    fn combine(&mut self, other: ElementVector<G>) {
        *self ^= other;
    }
    fn empty(length: usize) -> ElementVector<G> {
        ElementVector(repeat_with(G::identity).take(length).collect())
    }
}

impl<T> Accumulatable for Vec<T>
where
    T: Accumulatable,
{
    type Parameters = (usize, T::Parameters);

    fn combine(&mut self, other: Vec<T>) {
        assert_eq!(self.len(), other.len());
        for (this, that) in self.iter_mut().zip(other.into_iter()) {
            this.combine(that);
        }
    }

    fn empty((length, subparams): (usize, T::Parameters)) -> Self {
        repeat_with(|| T::empty(subparams.clone()))
            .take(length)
            .collect()
    }
}

pub struct Accumulator<D> {
    lock: RwLock<(D, usize)>,
}

impl<D> Accumulator<D>
where
    D: Accumulatable + Clone,
{
    pub fn new(accum: D) -> Accumulator<D> {
        let data = (accum, 0_usize);
        Accumulator {
            lock: RwLock::new(data),
        }
    }

    pub async fn accumulate(&self, data: D) -> usize {
        let mut lock = self.lock.write().await;
        let tuple: &mut (D, usize) = lock.deref_mut();
        let state = &mut tuple.0;
        let count = &mut tuple.1;

        state.combine(data);
        *count += 1;
        *count
    }

    pub async fn get(&self) -> D {
        let lock = self.lock.read().await;
        let (state, _) = lock.deref();
        state.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MyData(u8);

    impl Accumulatable for MyData {
        type Parameters = ();

        fn combine(&mut self, other: MyData) {
            (*self).0 += other.0;
        }

        fn empty(_: ()) -> Self {
            MyData(0)
        }
    }

    #[tokio::test]
    async fn test_accumulator_get_empty() {
        let accumulator = Accumulator::new(MyData::empty(()));

        assert_eq!(accumulator.get().await, MyData(0));
    }

    #[tokio::test]
    async fn test_accumulator_accumulate_identity() {
        let accumulator = Accumulator::new(MyData::empty(()));

        accumulator.accumulate(MyData::empty(())).await;

        assert_eq!(accumulator.get().await, MyData(0));
    }

    #[tokio::test]
    async fn test_accumulator_accumulate_unit() {
        let accumulator = Accumulator::new(MyData::empty(()));
        let count = 10;

        for _ in 0..count {
            accumulator.accumulate(MyData(1)).await;
        }

        assert_eq!(accumulator.get().await, MyData(count as u8));
    }

    #[tokio::test]
    async fn test_accumulator_vec() {
        let data: Vec<MyData> = vec![MyData(0); 3];
        let accumulator = Accumulator::new(data);

        let data = vec![MyData(0), MyData(1), MyData(2)];
        accumulator.accumulate(data.clone()).await;
        accumulator.accumulate(data).await;

        assert_eq!(
            accumulator.get().await,
            vec![MyData(0), MyData(2), MyData(4)]
        );
    }
}
