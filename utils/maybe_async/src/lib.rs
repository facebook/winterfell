// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Expr, ItemFn, TraitItemFn};

/// Parses a function (regular or trait) and conditionally adds the `async` keyword depending on
/// the `async` feature flag being enabled.
///
/// For example:
/// ```ignore
/// trait ExampleTrait {
///     #[maybe_async]
///     fn say_hello(&self);
///
///     #[maybe_async]
///     fn get_hello(&self) -> String;
/// }
///
///
/// #[maybe_async]
/// fn hello_world() {
///     // ...
/// }
/// ```
///
/// When the `async` feature is enabled, will be transformed into:
/// ```ignore
/// trait ExampleTrait {
///     async fn say_hello(&self);
///
///     async fn get_hello(&self) -> String;
/// }
///
///
/// async fn hello_world() {
///     // ...
/// }
/// ```
#[proc_macro_attribute]
pub fn maybe_async(_attr: TokenStream, input: TokenStream) -> TokenStream {
    if let Ok(func) = syn::parse::<ItemFn>(input.clone()) {
        if cfg!(feature = "async") {
            let ItemFn { attrs, vis, sig, block } = func;
            quote! {
                #(#attrs)* #vis async #sig { #block }
            }
            .into()
        } else {
            quote!(#func).into()
        }
    } else if let Ok(func) = syn::parse::<TraitItemFn>(input.clone()) {
        if cfg!(feature = "async") {
            let TraitItemFn { attrs, sig, default, semi_token } = func;
            quote! {
                #(#attrs)* async #sig #default #semi_token
            }
            .into()
        } else {
            quote!(#func).into()
        }
    } else {
        input
    }
}

/// Parses an expression and conditionally adds the `.await` keyword at the end of it depending on
/// the `async` feature flag being enabled.
///
/// ```ignore
/// #[maybe_async]
/// fn hello_world() {
///     // Adding `maybe_await` to an expression
///     let w = maybe_await!(world());
///
///     println!("hello {}", w);
/// }
///
/// #[maybe_async]
/// fn world() -> String {
///     "world".to_string()
/// }
/// ```
///
/// When the `async` feature is enabled, will be transformed into:
/// ```ignore
/// async fn hello_world() {
///     let w = world().await;
///
///     println!("hello {}", w);
/// }
///
/// async fn world() -> String {
///     "world".to_string()
/// }
/// ```
#[proc_macro]
pub fn maybe_await(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as Expr);

    let quote = if cfg!(feature = "async") {
        quote!(#item.await)
    } else {
        quote!(#item)
    };

    quote.into()
}
