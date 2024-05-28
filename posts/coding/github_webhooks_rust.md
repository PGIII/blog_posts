+++
draft = true
+++

# Implementing GitHub Webhooks in Rust With Axum

Webhooks are a way for GitHub repositories to notify web servers for various events such as pushes to the repository.
In this post we'll go over how to implement these in Rust Using Axum framework.

The code in here is only the code required for the webhook it's self.
It's assumed you have an existing Axum app that you want to expand.
Luckily Axum makes it easy to have nested routers, so we can implement all the hooks on their own router and nest it into the main router.

You can find more info on Axum at their [doc.rs page](https://docs.rs/axum/latest/axum/index.html)

## State

In order to verify the hook is sent from GitHub, the payload is signed with a Secret using HMAC SHA256.
So the first thing we need to do is create a state that can hold the secret.
Let's create a struct that is can be cloned, which will be passed to the Axum router allowing it to be shared between handlers.

```rust
#[derive(Clone)]
struct HookState {
    secret: SecretString,
}

```

Here we're using SecretString which comes from the [secrecy](https://crates.io/crates/secrecy) crate to help prevent our secret.
This state is actually separate from our main app state.
Allowing us to make sure the hooks are only using the state they need, as well as keeping the GitHub secret out of the main state.

## Router

Now let's take our state and make a router that uses is.
In Axum nested routers can have a separate state, so we'll create a router function that returns a new hooks router.
The main code can all this to get hooks router that can be nested into the main router.

```rust
pub fn router(
    secret: SecretString,
) -> Router {
    let state = HookState {
        secret,
    };
    Router::new()
        .route("/handle-git-hook", post(handle_git_hook))
        .with_state(state)
}

```

This function is pretty straight forward, it only takes in 1 parameter the secret.
Which means the main code is responsible for getting the secret E.g. loading it from an environmental variable.

Next we create a state with the secret and create a new router with 1 post route using the state we just created.
Rust doesn't require explicit return statements, by leaving out the ';' the router that is created will be returned.

Now that we have a router and state we need to create the function the route is referencing.

## Request Handler and Verifying The Signature

Finally, we can write our request handler, but how do we go about verifying the hook?
First is to get the signature that was sent, this should be in the header with the name "x-hub-signature-256".

_Github also currently sends a version of the signature hashed with SHA1, however at the time of writing the SHA256 version is what is recommended to use, and the older version is kept around for compatibility's sake_

So let's try to extract that header, and return an unauthorized error code if it's missing

```rust

async fn handle_git_hook(State(state): State<HookState>, headers: HeaderMap, body: String) -> Response {
    if let Some(in_sig) = headers.get("x-hub-signature-256") {
        //...
    } else {
        (StatusCode::UNAUTHORIZED, "missing x-hub-signature-256").into_response()
    }
```

Ok there's probably a lot to explain here since is the first look at our function signature.
First off what is going on with `State(state): State<HookState>`?
This is called an extractor in Axum, basically saying we are expecting a `state` of type `HookState`.
Taking advantage of pattern matching to extract out of the `State` type and into our `state` variable.
We actually don't need this quite yet so lets look at the next two params.
Headers is how we access the headers, and body is the payload of the request in a string.
Axum with handle getting these from the request and passing them to our handler here.

The only one really need right now is the headers.
Since they're stored in a map we can just use the `get` method to look up our siganture header by its name.
If the function returns none then we return an unauthorized response.
Here we use a tuple of a status code and a string.
The string will be the body of the response, and the status code the status code.
This is a pretty common way to return a response code other than 200 and we'll use it a few times for error paths here.

This is where the return type Response comes in.
Instead of return `impl IntoResponse`, which says that our return type can be transformed into a response.
We return a `Resonse` already built, allowing use to have multiple types returned as long as `into_response` is called on them before
returning.

The reason we have to do this is that `impl` generates a function based on all types that implement `IntoResponse`.
Meaning that all returns paths are expected to return the same Type.
You can work around this using dynamic dispatch, but simply returning a Response removes the need for it at the expense of needing to call `into_response` first.

```rust
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::post,
    Router,
};
use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;

#[derive(Clone)]
struct HookState {
    secret: SecretString,
}

pub fn router(
    secret: SecretString,
) -> Router {
    let state = HookState {
        secret,
    };
    Router::new()
        .route("/handle-git-hook", post(handle_git_hook))
        .with_state(state)
}

pub type HmacSha256 = Hmac<Sha256>;
async fn handle_git_hook(State(state): State<HookState>, headers: HeaderMap, body: String) -> Response {
    if let Some(in_sig) = headers.get("x-hub-signature-256") {
        match HmacSha256::new_from_slice(state.secret.expose_secret().as_bytes()) {
            Ok(mut mac) => {
                mac.update(body.as_bytes());
                let in_sig = in_sig.to_str().unwrap();
                match hex::decode(in_sig.strip_prefix("sha256=").unwrap().as_bytes()) {
                    Ok(decoded) => match mac.verify_slice(&decoded) {
                        Ok(()) => {
                            // Do what you want with the hook here we now know its valid
                            todo!()
                        },
                        Err(_) => (StatusCode::UNAUTHORIZED, "Invalid secret").into_response(),
                    },
                    Err(_) => (StatusCode::UNAUTHORIZED, "Couldn't decode secret").into_response(),
                }
            }
            Err(e) => {
                tracing::error!("could not build mac: {e}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An error occured validating payload",
                )
                    .into_response()
            }
        }
    } else {
        (StatusCode::UNAUTHORIZED, "missing x-hub-signature-256").into_response()
    }
}
```
