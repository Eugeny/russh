#[cfg(not(target_arch = "wasm32"))]
pub use native::*;
#[cfg(target_arch = "wasm32")]
pub use wasm::*;

#[derive(Debug)]
pub struct JoinError {
    #[cfg(not(target_arch = "wasm32"))]
    inner: tokio::task::JoinError,
    #[cfg(target_arch = "wasm32")]
    inner: tokio::sync::oneshot::error::RecvError,
}

impl std::fmt::Display for JoinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "JoinError: {}", self.inner)
    }
}

impl std::error::Error for JoinError {}

pub struct JoinHandle<T>
where
    T: Send,
{
    #[cfg(target_arch = "wasm32")]
    handle: tokio::sync::oneshot::Receiver<T>,
    #[cfg(not(target_arch = "wasm32"))]
    handle: tokio::task::JoinHandle<T>,
}

#[cfg(target_arch = "wasm32")]
pub mod wasm {

    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Poll},
    };

    use crate::runtime::{JoinError, JoinHandle};

    pub fn spawn<F, T>(future: F) -> JoinHandle<T>
    where
        F: Future<Output = T> + 'static + Send,
        T: Send + 'static,
    {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        wasm_bindgen_futures::spawn_local(async {
            let result = future.await;
            let result = sender.send(result);
            if result.is_err() {
                panic!("Failed to send result to receiver");
            }
        });

        JoinHandle { handle: receiver }
    }

    impl<T> Future for JoinHandle<T>
    where
        T: Send,
    {
        type Output = Result<T, JoinError>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            match Pin::new(&mut self.handle).poll(cx) {
                Poll::Ready(Ok(val)) => Poll::Ready(Ok(val)),
                Poll::Ready(Err(e)) => Poll::Ready(Err(JoinError { inner: e })),
                Poll::Pending => Poll::Pending,
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub mod native {

    use crate::runtime::{JoinError, JoinHandle};

    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Poll},
    };

    pub fn spawn<F, T>(future: F) -> JoinHandle<T>
    where
        F: Future<Output = T> + 'static + Send,
        T: Send + 'static,
    {
        let handle = tokio::spawn(future);
        JoinHandle { handle }
    }

    impl<T> Future for JoinHandle<T>
    where
        T: Send,
    {
        type Output = Result<T, JoinError>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            match Pin::new(&mut self.handle).poll(cx) {
                Poll::Ready(Ok(val)) => Poll::Ready(Ok(val)),
                Poll::Ready(Err(e)) => Poll::Ready(Err(JoinError { inner: e })),
                Poll::Pending => Poll::Pending,
            }
        }
    }
}
