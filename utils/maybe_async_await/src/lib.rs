use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Expr, ItemFn, TraitItemFn};

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
