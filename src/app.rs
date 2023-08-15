use std::{fs, sync::Arc};
use ethnum::serde::bytes::ne;
use tokio::sync::Mutex;
use crate::{node, account, block, msg, state};
use axum::{Router, routing, extract::FromRef};
use serde::{Serialize, Deserialize};
use tokio::time;
use std::fmt::Debug;

mod handlers {
    use super::*;

    use std::{sync::Arc, collections::HashMap, vec};
    use sha2::{Sha256, Digest};
    use axum::{http, extract, response};
    use ethnum::U256;

    pub async fn index(
        extract::State(appstate): extract::State<AppState>
    ) -> response::Html<String> {
        let head = appstate.client.node.get_head().await;
        let page = appstate.templates
            .get_template("index")
            .unwrap()
            .render(minijinja::context!{ 
                node_id => appstate.client.node.kp.kp.public.as_bytes()[0],
                peers => *appstate.client.neighbors.lock().await,
                round => head.block.sheader.msg.data.round,
                last_leader => head.block.sheader.from.as_bytes()[0],
                account_data => head.state.accounts.get(&Sha256::digest(appstate.client.node.kp.kp.public.as_bytes())).unwrap(),
                num_slots => head.state.validators.iter().filter(|s| s.owner == appstate.client.node.kp.kp.public).count()
            })
            .unwrap();
        response::Html(page)
    }

    pub async fn p2p(
        extract::State(client): extract::State<Arc<Client>>,
        body: String
    ) {
        let res: Result<InitMessage, _> = serde_json::from_str(&body);
        match res {
            Ok(init) => match init {
                InitMessage::Txn(t) => {
                    let (resp, opt_bcast) = client.node.receive_txns(t).await;
                    if let Some(bcast) = opt_bcast {
                        client.broadcast(InitMessage::Txn(bcast)).await;
                    }
                },
                InitMessage::Chain(c) => {

                },
                _ => { panic!("todo") }
            },
            _ => { panic!("todo") }
        }
    }

    pub async fn explorer(
        extract::State(appstate): extract::State<AppState>
    ) -> response::Html<String> {
        response::Html(appstate.templates.get_template("explorer").unwrap().render(minijinja::context!{ max_slot => state::VALIDATOR_SLOTS - 1 }).unwrap())
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct AccountForm {
        address: String
    }

    pub async fn api_account(
        extract::State(appstate): extract::State<AppState>,
        extract::Query(params): extract::Query<AccountForm>
    ) -> response::Html<String> {
        let resp = match u256_parser(&params.address) {
            Err(e) => e,
            Ok(x) => {
                match appstate.client.node.get_head().await
                    .state.accounts.get(&x.to_be_bytes()).unwrap() {
                        Some(a) => serde_json::to_string(a).unwrap(),
                        None => "Account not found".to_owned()
                    }
            }
        };
        response::Html(
            appstate.templates.get_template("response").unwrap()
                .render(minijinja::context!{ response => resp, id => "account_response" }).unwrap()
        )
    }

    pub async fn api_account_search(
        extract::State(appstate): extract::State<AppState>,
        extract::Query(params): extract::Query<AccountForm>
    ) -> response::Html<String> {
        println!("hi");
        let mut chars = params.address.chars();
        let vec = if chars.next() != Some('0') || chars.next() != Some('x') {
            Vec::default()
        } else {
            let mut vec = Vec::<u8>::default();
            for hex in chars.map(|c| c.to_digit(16)) {
                match hex {
                    None => {
                        vec = Vec::default();
                        break;
                    },
                    Some(x) => vec.push(x as u8)
                }
            }
            if vec.is_empty() {
                Vec::default()
            } else {
                match appstate.client.node.get_head().await
                    .state.accounts.get_subtrie(&vec).unwrap() {
                        None => Vec::default(),
                        Some((sub, path)) => {
                            sub.entry_iter()
                                .map(|(p, _)| {
                                    let mut full = path.clone();
                                    full.extend(&p);
                                    nibble_array_to_hex(&full)
                                })
                                .take(10).collect::<Vec<_>>()
                        }
                    }
            }
        };
        response::Html(
            appstate.templates.get_template("search-response").unwrap()
                .render(minijinja::context!{ response => vec, id => "search_response" }).unwrap()
        )
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct ValidatorForm {
        slot: String
    }

    pub async fn api_validator(
        extract::State(appstate): extract::State<AppState>,
        extract::Query(params): extract::Query<ValidatorForm>
    ) -> response::Html<String> {
        let resp = match u32::from_str_radix(&params.slot, 10) {
            Err(e) => e.to_string(),
            Ok(x) => {
                match appstate.client.node.get_head().await
                    .state.validators.get(&x.to_be_bytes()).unwrap() {
                        Some(a) => serde_json::to_string(a).unwrap(),
                        None => "Slot is empty".to_owned()
                    }
            }
        };
        response::Html(
            appstate.templates.get_template("response").unwrap()
                .render(minijinja::context!{ response => resp, id => "validator_response" }).unwrap()
        )
    }

    pub async fn faucet(
        extract::State(appstate): extract::State<AppState>
    ) -> response::Html<String> {
        println!("fauc");
        response::Html(appstate.templates.get_template("faucet").unwrap().render(minijinja::context!{ }).unwrap())
    }

    pub fn u256_parser(s: &str) -> Result<U256, String> {
        if s.chars().nth(0) != Some('0') || s.chars().nth(1) != Some('x') {
            Err("Address should be prefixed with 0x".to_owned())
        } else {
            if s[2..].len() != 64 {
                Err("Address should be 64 hex digits".to_owned())
            } else {
                match U256::from_str_hex(s) {
                    Err(_) => Err("Invalid hex digit".to_owned()),
                    Ok(x) => Ok(x)
                }
            }
        }
    }

    pub fn nibble_array_to_hex(arr: &[u8]) -> String {
        let mut hex = "0x".to_string();
        for nib in arr {
            hex.push(char::from_digit(*nib as u32, 16).unwrap());
        };
        hex
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct FaucetForm {
        address: String,
        amount: String
    }

    pub async fn api_faucet(
        extract::State(appstate): extract::State<AppState>,
        extract::Json(params): extract::Json<FaucetForm>
    ) -> response::Html<String> {
        let resp = {
            match u32::from_str_radix(&params.amount, 10) {
                Err(e) => e.to_string(),
                Ok(amount) => {
                    match u256_parser(&params.address) {
                        Err(e) => e,
                        Ok(hex) => {
                            let mut nonce = appstate.client.node.nonce.lock().await;
                            let txn = appstate.client.node.kp.send_acc(
                                hex.to_be_bytes(),
                                amount, 
                                *nonce
                            );
                            *nonce += 1;
                            appstate.client.node.receive_txns(
                                msg::txn::Broadcast{ txns: Vec::from([txn]) }
                            ).await;
                            "Request was successful. Account will be credited in a few seconds.".to_owned()
                        }
                    }
                }
            }
        };
        response::Html(
            appstate.templates
                .get_template("response")
                .unwrap()
                .render(minijinja::context!{ response => resp, id => "response" })
                .unwrap()
        )
    }
}

// The kinds of messages which a client can send to initiate a conversation
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum InitMessage {
    Txn(msg::txn::Broadcast),
    Chain(msg::chain::Broadcast),
    Resync(msg::resync::Request),
    Batch(msg::batch::Request),
}

pub struct Client {
    pub node: node::Node,
    pub neighbors: Mutex<Vec<String>>,
}

#[derive(Clone)]
pub struct AppState {
    client: Arc<Client>,
    templates: minijinja::Environment<'static>
}

impl FromRef<AppState> for Arc<Client> {
    fn from_ref(appstate: &AppState) -> Arc<Client> {
        appstate.client.clone()
    }
}

impl Client {
    pub fn new(kp: account::Keypair, gen: &block::Snap, nonce: u32) -> Self {
        Self {
            node: node::Node::new(kp, gen.clone(), nonce),
            neighbors: Mutex::new(Vec::default())
        }
    }

    pub async fn run(self, addr: &str) {
        // Load templates
        let mut templates = minijinja::Environment::new();
        templates.add_template_owned("index", fs::read_to_string("templates/index.html").unwrap()).unwrap();
        templates.add_template_owned("faucet", fs::read_to_string("templates/faucet.html").unwrap()).unwrap();
        templates.add_template_owned("explorer", fs::read_to_string("templates/explorer.html").unwrap()).unwrap();
        templates.add_template_owned("response", fs::read_to_string("templates/response.html").unwrap()).unwrap();
        templates.add_template_owned("search-response", fs::read_to_string("templates/search-response.html").unwrap()).unwrap();
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
        let client = Arc::new(self);
        let app = Router::new()
            .route("/", routing::get(handlers::index))
            .route("/faucet.html", routing::get(handlers::faucet))
            .route("/explorer.html", routing::get(handlers::explorer))
            .route("/p2p/txn", routing::post(handlers::p2p_txn))
            .route("/p2p/chain", routing::post(handlers::p2p_chain))
            .route("/api/faucet", routing::post(handlers::api_faucet))
            .route("/api/account", routing::get(handlers::api_account))
            .route("/api/account_search", routing::get(handlers::api_account_search))
            .route("/api/validator", routing::get(handlers::api_validator))
            .with_state(AppState { client: client.clone(), templates });
        let _ = tokio::spawn(
            axum::Server::bind(&addr.parse().unwrap())
                .serve(app.into_make_service())
        );
        loop {
            interval.tick().await;
            if let Some(send) = client.node.tick().await {
                client.broadcast(InitMessage::Chain(send.str)).await;
            }
        }
    }

    pub async fn broadcast(&self, message: InitMessage) {
        println!("I just bcasted {:?}", message);
        let ser = serde_json::to_string(&message).unwrap();
        let neighbs = &*self.neighbors.lock().await;
        let mut handles = Vec::with_capacity(neighbs.len());
        for neighbor in neighbs {
            let client = reqwest::Client::new();
            println!("sending to {:?}", neighbor);
            let fut = client
                .post(format!("http://{}/p2p", neighbor))
                .body(ser.clone())
                .send();
            handles.push(tokio::spawn(fut));
        }
        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            results.push(handle.await.unwrap());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{account, block};

    #[tokio::test]
    async fn app() {
        let genesis = block::Snap::default();

        let kp = account::Keypair::default();
        let alice = Client::new(kp, &genesis, state::JENNY_SLOTS);
        alice.neighbors.lock().await.push(String::from("127.0.0.1:3001"));
        let fut = alice.run("127.0.0.1:3000");
        let alice_fut = tokio::spawn(fut);

        let kp = account::Keypair::gen();
        let bob = Client::new(kp, &genesis, 0);
        bob.neighbors.lock().await.push(String::from("127.0.0.1:3000"));
        let fut = bob.run("127.0.0.1:3001");
        let bob_fut = tokio::spawn(fut);

        // time::sleep(time::Duration::from_millis(10_000)).await; panic!();

        let _ = alice_fut.await;
        let _ = bob_fut.await;
        panic!();
    }
}