# Winter maybe-async

This crate contains the `maybe_async` procedural attribute macro and the `maybe_await` procedural macro which abstract away Rust sync/async.

## maybe_async

The `maybe_async` macro will conditionally add the `async` keyword to a function it marks depending on the `async` feature being enabled. To generate the asynchronous version, enable the `async` feature on the crate. If the `async` feature is off, the synchronous version will be generated. For example,

```rust
// Adding `maybe_async` to trait functions
trait ExampleTrait {
    #[maybe_async]
    fn say_hello(&self);

    #[maybe_async]
    fn get_hello(&self) -> String;
}

// Adding `maybe_async` to regular functions
#[maybe_async]
fn hello_world() {
    // ...
}
```

When the `async` feature is enabled, the above code will be transformed into:

```rust
trait ExampleTrait {
    async fn say_hello(&self);

    async fn get_hello(&self) -> String;
}

async fn hello_world() {
    // ...
}
```

## maybe_await

To complement `maybe_async` we also have the `maybe_await` procedural macro that conditionally adds the `.await` keyword to the end of an expression depending on the `async` feature flag.

```rust
#[maybe_async]
fn hello_world() {
    // Adding `maybe_await` to an expression
    let w = maybe_await!(world());

    println!("hello {}", w);
}

#[maybe_async]
fn world() -> String {
    "world".to_string()
}
```

When the `async` feature is enabled, the above code will be transformed into:

```rust
async fn hello_world() {
    let w = world().await;

    println!("hello {}", w);
}

async fn world() -> String {
    "world".to_string()
}
```

## maybe_async_trait

The `maybe_async_trait` macro can be applied to traits, and it will conditionally add the `async` keyword to trait methods annotated with `#[maybe_async]`, depending on the async feature being enabled. It also applies `#[async_trait::async_trait(?Send)]` to the trait or impl block when the async feature is on.

For example:

```rust
// Adding `maybe_async_trait` to a trait definition
#[maybe_async_trait]
trait ExampleTrait {
    #[maybe_async]
    fn hello_world(&self);

    fn get_hello(&self) -> String;
}

// Adding `maybe_async_trait` to an implementation of the trait
#[maybe_async_trait]
impl ExampleTrait for MyStruct {
    #[maybe_async]
    fn hello_world(&self) {
        // ...
    }

    fn get_hello(&self) -> String {
        // ...
    }
}
```

When `async` is set, it gets transformed into:

```rust
#[async_trait::async_trait(?Send)]
trait ExampleTrait {
    async fn hello_world(&self);

    fn get_hello(&self) -> String;
}

#[async_trait::async_trait(?Send)]
impl ExampleTrait for MyStruct {
    async fn hello_world(&self) {
        // ...
    }

    fn get_hello(&self) -> String {
        // ...
    }
}
```

## License

This project is [MIT licensed](../../LICENSE).
