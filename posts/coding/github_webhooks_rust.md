+++
cover_image_url = "post_assets/rustacean-flat-happy.png"
+++

# Implementing GitHub Webhooks in Rust With Axum

Webhooks are a way for GitHub repositories to notify web servers for various events such as pushes to the repository.
In this post we'll go over how to implement these in Rust Using the Axum framework.

The code in here is only the code required for the webhook it's self.
It's assumed you have an existing Axum app that you want to expand.
Luckily Axum makes it easy to have nested routers, so we can implement all the hooks on their own router and nest it into the main router.

You can find more info on Axum at their [doc.rs page](https://docs.rs/axum/latest/axum/index.html)

## State

In order to verify the hook is sent from GitHub, the payload is signed with a Secret using HMAC SHA256.
So the first thing we need to do is create a state that can hold the secret.
Let's create a struct which will be passed to the Axum router to be shared between handlers.

```rust
#[derive(Clone)]
struct HookState {
    secret: SecretString,
}

```

Here we're using SecretString which comes from the [secrecy](https://crates.io/crates/secrecy) crate to help protect our secret.
We also need to derive clone so that it can be passed to handlers correctly.
This state is actually separate from our main app state.
Allowing us to make sure the hooks are only using the state they need, as well as keeping the GitHub secret out of the main state.

## Router

Now let's take our state and make a router that uses is.
In Axum nested routers can have a separate state, so we'll create a router function that returns a new hooks router.
The main code can call this to get the hook's router that can be nested into the main router.

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
headers is how we access the headers, and body is the payload of the request in a string.
Axum with handle getting these from the request and passing them to our handler here.

The only one we really need right now is the headers.
Since they're stored in a map we can just use the `get` method to look up our signature header by its name.
If the function returns none then we return an unauthorized response.
Here we use a tuple of a status code and a string.
The string will be the body of the response, and the status code the status code.
This is a pretty common way to return a response code other than 200, and we'll use it a few times for error paths here.

This is where the return type Response comes in.
Instead of return `impl IntoResponse`, which says that our return type can be transformed into a response.
We return a `Resonse` already built, allowing us to have multiple types returned as long as `into_response` is called on them before
returning.

The reason we have to do this is that `impl` generates a function based on all types that implement `IntoResponse`.
Meaning that all returns paths are expected to return the same Type.
You can work around this using dynamic dispatch, but simply returning a Response removes the need for it at the expense of needing to call `into_response` first.

Now let's initialize the HMAC with our secret and then feed it in the body.
This will create a signature that we can compare with the one sent by GitHub.

```rust
pub type HmacSha256 = Hmac<Sha256>;
async fn handle_git_hook(State(state): State<HookState>, headers: HeaderMap, body: String) -> Response {
    if let Some(in_sig) = headers.get("x-hub-signature-256") {
        match HmacSha256::new_from_slice(state.secret.expose_secret().as_bytes()) {
            Ok(mut mac) => {
                mac.update(body.as_bytes());
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

The HMAC type may return an error, in this case I choose to return an internal server error and log the error.
If it returns no error, we then call update with the body string, passing it in as bytes.

Lastly we need to verify the signature, however there is one issue left to solve.
The signature we get from GitHub is encoded as the hex string representation of the underlying binary data, but the verify function expects the binary form in an array of bytes.
The string also starts with sha256= so we need to split that off and then decode the remaining string.

```rust
pub type HmacSha256 = Hmac<Sha256>;
async fn handle_git_hook(State(state): State<HookState>, headers: HeaderMap, body: String) -> Response {
    if let Some(in_sig) = headers.get("x-hub-signature-256") {
        match HmacSha256::new_from_slice(state.secret.expose_secret().as_bytes()) {
            Ok(mut mac) => {
                mac.update(body.as_bytes());
                if let Some(sig_sep) = in_sig.strip_prefix(b"sha256=") {
                    match hex::decode(sig_sep) {
                        Ok(decoded) => match mac.verify_slice(&decoded) {
                            Ok(()) => {
                                //.. Do what you want with this hook
                            },
                            Err(_) => (StatusCode::UNAUTHORIZED, "Invalid secret").into_response(),
                        },
                        Err(_) => {
                            (StatusCode::UNAUTHORIZED, "Couldn't decode secret").into_response()
                        }
                    }
                } else {
                    (
                        StatusCode::BAD_REQUEST,
                        "could not parse x-hub-signature-256 as str",
                    )
                        .into_response()
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

After decoding the hex string we pass it to verify slice, this function checks a signature against what it's calculated so far.
At this point you have a verified request and can do whatever you want with the request in the final `Ok`.

Full Code can be found below

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
        let in_sig = in_sig.as_bytes();
        match HmacSha256::new_from_slice(state.secret.expose_secret().as_bytes()) {
            Ok(mut mac) => {
                mac.update(body.as_bytes());
                if let Some(sig_sep) = in_sig.strip_prefix(b"sha256=") {
                    match hex::decode(sig_sep) {
                        Ok(decoded) => match mac.verify_slice(&decoded) {
                            Ok(()) => {
                                //.. Do what you want with this hook
                            },
                            Err(_) => (StatusCode::UNAUTHORIZED, "Invalid secret").into_response(),
                        },
                        Err(_) => {
                            (StatusCode::UNAUTHORIZED, "Couldn't decode secret").into_response()
                        }
                    }
                } else {
                    (
                        StatusCode::BAD_REQUEST,
                        "could not parse x-hub-signature-256 as str",
                    )
                        .into_response()
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

## Closing Remarks

### Nesting

At this point you may be thinking "Wow that's a lot of nesting" in which case you'd be right.
There are a few ways you can go about solving that with Axum.
Usually I would use the `?` operator to return on errors and have an outer function turn those errors into a response.
The more Axum way to go about it would be to create a custom extractor that does all of this before it even gets to the handler.
At the end of the day leaving it nested like this means it can all fit in one function which is easier to follow in a blog post.

### Parsing The Body

For my needs I don't really care about the contents of the body just that the webhook is valid.
So this code does no converting of the body to a struct,
this could be done pretty easily with [JSON Serde](https://github.com/serde-rs/json).

### Testing

Thanks to the Axum router this is pretty straightforward to test, GitHub even provides some test data for the hashing.
Here is an example of such test.

```rust
#[tokio::test]
async fn test_git_hook() {
    let blog_webhook_secret = SecretString::from_str("It's a Secret to Everybody").unwrap();
    let router = router(
        blog_webhook_secret,
    )
    .await
    .unwrap();

    let res = router
        .oneshot(
            Request::builder()
                .method(method::Method::POST)
                .uri("/handle-git-hook")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header(
                    "X-Hub-Signature-256",
                    "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17",
                )
                .body(Body::new("Hello, World!".to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}
```

The router built here can be the hooks router we created or your main router depending on your needs.
