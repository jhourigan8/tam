use std::sync::Arc;

use crate::{node, account, block};
use axum::{extract, Router, routing};
use tokio::time;

mod handlers {
    use std::sync::{Arc, Mutex};
    use sha2::Digest;

    use axum::{extract, routing, Router, Extension};
    use sha2::Sha256;
    use crate::{node, account, block, app};

    pub async fn root(extract::State(client): extract::State<Arc<app::Client>>) -> String {
        let head = client.node.get_head().await;
        String::from(
            format!(
"This is node {:?}.
My peers are {:?}.
Last block received was round {:?} led by {:?}.
My current account data is {:?}.", 
                client.node.kp.kp.public.as_bytes()[0],
                client.neighbors,
                head.block.sheader.msg.data.round,
                head.block.sheader.from.as_bytes()[0],
                head.state.accounts.get(&Sha256::digest(client.node.kp.kp.public.as_bytes())).unwrap()
            )
        )
    }

    pub async fn receive(
        extract::State(client): extract::State<Arc<app::Client>>,
        body: String
    ) {
        println!("Bcast received!");
        if let Some(message) = client.node.receive(body).await {
            client.broadcast(message).await;
        }
    }
}

pub struct Client {
    node: node::Node,
    neighbors: Vec<String>,
}

impl Client {
    fn new(kp: account::Keypair, gen: &block::Snap) -> Self {
        Self {
            node: node::Node::new(kp, gen.clone()),
            neighbors: Vec::default()
        }
    }

    async fn run(self, addr: &str) {
        // Block time sync!
        let gen = self.node.get_head().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let wait_for = block::BLOCK_TIME - ((now - gen.block.sheader.msg.data.timestamp) % block::BLOCK_TIME);
        time::sleep(time::Duration::from_millis(wait_for)).await;
        // Now synced!
        let now = time::Instant::now();
        let mut interval = time::interval_at(now, time::Duration::from_millis(block::BLOCK_TIME));
        interval.tick().await;
        // Spin up server
        println!("spin!");
        let client = Arc::new(self);
        let app = Router::new()
            .route("/", routing::get(handlers::root))
            .route("/receive", routing::post(handlers::receive))
            .with_state(client.clone());
        let _ = tokio::spawn(
            axum::Server::bind(&addr.parse().unwrap())
                .serve(app.into_make_service())
        );
        loop {
            interval.tick().await;
            if let Some(message) = client.node.tick().await {
                println!("Tick bcast!");
                client.broadcast(message).await;
            }
        }
    }

    async fn broadcast(&self, message: String) {
        let mut handles = Vec::with_capacity(self.neighbors.len());
        for neighbor in &self.neighbors {
            let client = reqwest::Client::new();
            let fut = client.post(format!("http://{}/receive", neighbor))
                .body(message.clone())
                .send();
            handles.push(tokio::spawn(fut));
        }
        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            results.push(handle.await.unwrap());
        }
        println!("Bcast results: {:?}", results);
    }
}

mod tests {
    use std::sync::{Arc, Mutex};
    use tokio::time;

    use axum::{extract, routing, Router, Extension};
    use crate::{node, account, block, app};

    async fn root(extract::State(client): extract::State<Arc<app::Client>>) -> String {
        let head = client.node.get_head().await;
        String::from(
            format!(
                "This is node {:?}.\nMy peers are {:?}.\nLast block received was round {:?} led by {:?}.", 
                client.node.kp.kp.public.as_bytes()[0],
                client.neighbors,
                head.block.sheader.msg.data.round,
                head.block.sheader.from.as_bytes()[0]
            )
        )
    }

    async fn receive(
        extract::State(client): extract::State<Arc<app::Client>>,
        body: String
    ) {
        if let Some(message) = client.node.receive(body).await {
            client.broadcast(message).await;
        }
    }

    #[tokio::test]
    async fn app() {
        let genesis = block::Snap::default();

        let kp = account::Keypair::default();
        let mut alice = app::Client::new(kp, &genesis);
        alice.neighbors.push(String::from("127.0.0.1:3001"));
        let fut = alice.run("127.0.0.1:3000");
        let alice_fut = tokio::spawn(fut);

        let kp = account::Keypair::gen();
        let mut bob = app::Client::new(kp, &genesis);
        bob.neighbors.push(String::from("127.0.0.1:3000"));
        let fut = bob.run("127.0.0.1:3001");
        let bob_fut = tokio::spawn(fut);
        
        time::sleep(time::Duration::from_millis(10_000)).await;
        panic!();

        let _ = alice_fut.await;
        let _ = bob_fut.await;
    }
}