// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{parse_macro_input, ImplItem, TraitItem};

mod parse;
use parse::Item;

mod visit;
use visit::AsyncAwaitRemoval;

/// maybe_async attribute macro
#[proc_macro_attribute]
pub fn maybe_async(_args: TokenStream, input: TokenStream) -> TokenStream {
    let mut item = parse_macro_input!(input as Item);

    let token = if cfg!(feature = "async") {
        convert_async(&mut item)
    } else {
        convert_sync(&mut item)
    };

    token.into()
}

fn convert_sync(input: &mut Item) -> TokenStream2 {
    match input {
        Item::Impl(item) => {
            for inner in &mut item.items {
                if let ImplItem::Fn(ref mut method) = inner {
                    if method.sig.asyncness.is_some() {
                        method.sig.asyncness = None;
                    }
                }
            }
            AsyncAwaitRemoval.remove_async_await(quote!(#item))
        }
        Item::Trait(item) => {
            for inner in &mut item.items {
                if let TraitItem::Fn(ref mut method) = inner {
                    if method.sig.asyncness.is_some() {
                        method.sig.asyncness = None;
                    }
                }
            }
            AsyncAwaitRemoval.remove_async_await(quote!(#item))
        }
        Item::Fn(item) => {
            if item.sig.asyncness.is_some() {
                item.sig.asyncness = None;
            }
            AsyncAwaitRemoval.remove_async_await(quote!(#item))
        }
        Item::Static(item) => AsyncAwaitRemoval.remove_async_await(quote!(#item)),
    }
}

fn convert_async(input: &mut Item) -> TokenStream2 {
    match input {
        Item::Trait(item) => quote!(#[async_trait::async_trait]#item),
        Item::Impl(item) => quote!(#[async_trait::async_trait]#item),
        Item::Fn(item) => quote!(#item),
        Item::Static(item) => quote!(#item),
    }
}
