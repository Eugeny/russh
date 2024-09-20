use std::future::Future;

pub fn spawn<F>(future: F)
where
    F: Future<Output = ()> + 'static + Send,
{
    #[cfg(target_arch = "wasm32")]
    {
        wasm_bindgen_futures::spawn_local(future);
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        tokio::spawn(future);
    }
}
