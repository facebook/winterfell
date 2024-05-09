# Winter maybe-async
This crate contains a `maybe_async` proc macro that abstracts away sync/async. It is heavily based on [`maybe-async`](https://github.com/fMeow/maybe-async-rs).

The `maybe_async` macro will generate a synchronous or asynchronous version of the trait it is marking. To generate the asynchronous version, enable the `async` feature on the crate. If the `async` feature is off, the synchronous version will be generated. For example,

```rs
#[maybe_async]
trait ExampleTrait {
    async fn say_hello(&self) {
        let hello = self.get_hello().await;

        println!("{}", hello);
    }

    async fn get_hello(&self) -> String {
        "hello".into()
    }
}

// Generate code when `async` feature is turned ON
#[async_trait]
trait ExampleTrait {
    async fn say_hello(&self) {
        let hello = self.get_hello().await;

        println!("{}", hello);
    }

    async fn get_hello(&self) -> String {
        "hello".into()
    }
}

// Generate code when `async` feature is turned OFF
trait ExampleTrait {
    fn say_hello(&self) {
        let hello = self.get_hello();

        println!("{}", hello);
    }

    fn get_hello(&self) -> String {
        "hello".into()
    }
}
```

where `#[async_trait]` is the proc macro provided by the [`async-trait`](https://crates.io/crates/async-trait) crate. Notice how `#[maybe_async]` took care of removing the `.await` in the synchronous version of `say_hello()`.

`#[maybe_async]` can also mark `impl` blocks in a similar manner. For example,

```rs
struct ExampleStruct;

#[maybe_async]
impl ExampleTrait for ExampleStruct {
    async fn say_hello(&self) {
        println!("hello!");
    }
}

// Generate code when `async` feature is turned ON
#[async_trait]
impl ExampleTrait for ExampleStruct {
    async fn say_hello(&self) {
        println!("hello!");
    }
}

// Generate code when `async` feature is turned OFF
impl ExampleTrait for ExampleStruct {
    fn say_hello(&self) {
        println!("hello!");
    }
}

```

Finally, `#[maybe_async]` can be used on `fn` items, which works in an analogous way to the previous examples.

```rs
#[maybe_async]
async fn say_hello() {
    // ...
}
```

License
-------

This project is [MIT licensed](../../LICENSE).
