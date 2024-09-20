use std::io::ErrorKind;
use std::ops::Deref;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

#[derive(Debug)]
pub struct JoinError(Box<dyn std::error::Error + Send + Sync>);

impl Deref for JoinError {
    type Target = dyn std::error::Error + Send + Sync;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl std::fmt::Display for JoinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Default for JoinError {
    fn default() -> Self {
        Self(Box::new(std::io::Error::new(
            ErrorKind::Other,
            "aborted".to_string(),
        )))
    }
}

pub struct JoinHandle<T>
where
    T: Send,
{
    handle: tokio::sync::oneshot::Receiver<T>,
}

#[cfg(target_arch = "wasm32")]
macro_rules! spawn_impl {
    ($fn:expr) => {
        wasm_bindgen_futures::spawn_local($fn)
    };
}

#[cfg(not(target_arch = "wasm32"))]
macro_rules! spawn_impl {
    ($fn:expr) => {
        tokio::spawn($fn)
    };
}

pub fn spawn<F, T>(future: F) -> JoinHandle<T>
where
    F: Future<Output = T> + 'static + Send,
    T: Send + 'static,
{
    let (sender, receiver) = tokio::sync::oneshot::channel();
    spawn_impl!(async {
        let result = future.await;
        let _ = sender.send(result);
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
            Poll::Ready(Err(_)) => Poll::Ready(Err(JoinError::default())),
            Poll::Pending => Poll::Pending,
        }
    }
}
