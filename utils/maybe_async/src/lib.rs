// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Expr, ItemFn, TraitItemFn};

/// maybe_async procedural attribute macro
///
/// Parses a function (regular or trait) and conditionally adds the `async` keyword
/// depending on the `async` feature flag being enabled.
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

/// maybe_await procedural macro
///
/// Parses an expression and conditionally adds the `.await` keyword at the end of it
/// depending on the `async` feature flag being enabled.
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
