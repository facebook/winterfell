// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Expr, ImplItem, ItemFn, ItemImpl, ItemTrait, TraitItem, TraitItemFn};

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

/// Conditionally add `async` keyword to functions.
///
/// Parses a trait or an `impl` block and conditionally adds the `async` keyword to methods that
/// are annotated with `#[maybe_async]`, depending on the `async` feature flag being enabled.
/// Additionally, if applied to a trait definition or impl block, it will add
/// `#[async_trait::async_trait(?Send)]` to the it.
///
/// For example, given the following trait definition:
/// ```ignore
/// #[maybe_async_trait]
/// trait ExampleTrait {
///     #[maybe_async]
///     fn hello_world(&self);
///
///     fn get_hello(&self) -> String;
/// }
/// ```
///
/// And the following implementation:
/// ```ignore
/// #[maybe_async_trait]
/// impl ExampleTrait for MyStruct {
///     #[maybe_async]
///     fn hello_world(&self) {
///         // ...
///     }
///
///     fn get_hello(&self) -> String {
///         // ...
///     }
/// }
/// ```
///
/// When the `async` feature is enabled, this will be transformed into:
/// ```ignore
/// #[async_trait::async_trait(?Send)]
/// trait ExampleTrait {
///     async fn hello_world(&self);
///
///     fn get_hello(&self) -> String;
/// }
///
/// #[async_trait::async_trait(?Send)]
/// impl ExampleTrait for MyStruct {
///     async fn hello_world(&self) {
///         // ...
///     }
///
///     fn get_hello(&self) -> String {
///         // ...
///     }
/// }
/// ```
///
/// When the `async` feature is disabled, the code remains unchanged, and neither the `async`
/// keyword nor the `#[async_trait::async_trait(?Send)]` attribute is applied.
#[proc_macro_attribute]
pub fn maybe_async_trait(_attr: TokenStream, input: TokenStream) -> TokenStream {
    // Try parsing the input as a trait definition
    if let Ok(mut trait_item) = syn::parse::<ItemTrait>(input.clone()) {
        let output = if cfg!(feature = "async") {
            for item in &mut trait_item.items {
                if let TraitItem::Fn(method) = item {
                    // Remove the #[maybe_async] and make method async
                    method.attrs.retain(|attr| {
                        if attr.path().is_ident("maybe_async") {
                            method.sig.asyncness = Some(syn::token::Async::default());
                            false
                        } else {
                            true
                        }
                    });
                }
            }

            quote! {
                #[async_trait::async_trait(?Send)]
                #trait_item
            }
        } else {
            quote! {
                #trait_item
            }
        };

        return output.into();
    }
    // Check if it is an Impl block
    else if let Ok(mut impl_item) = syn::parse::<ItemImpl>(input.clone()) {
        let output = if cfg!(feature = "async") {
            for item in &mut impl_item.items {
                if let ImplItem::Fn(method) = item {
                    // Remove #[maybe_async] and make method async
                    method.attrs.retain(|attr| {
                        if attr.path().is_ident("maybe_async") {
                            method.sig.asyncness = Some(syn::token::Async::default());
                            false // Remove the attribute
                        } else {
                            true // Keep other attributes
                        }
                    });
                }
            }
            quote! {
                #[async_trait::async_trait(?Send)]
                #impl_item
            }
        } else {
            quote! {
                #[cfg(not(feature = "async"))]
                #impl_item
            }
        };

        return output.into();
    }

    // If input is neither a trait nor an impl block, emit a compile-time error
    quote! {
        compile_error!("`maybe_async_trait` can only be applied to trait definitions and trait impl blocks");
    }.into()
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
