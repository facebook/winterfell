// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! This file was heavily inspired by [`parse.rs`](https://github.com/fMeow/maybe-async-rs/blob/b32a81704f6d84576d77e06882a06570e7f38de9/src/parse.rs).

use proc_macro2::Span;
use syn::{
    parse::{discouraged::Speculative, Parse, ParseStream, Result},
    Attribute, Error, ItemFn, ItemImpl, ItemStatic, ItemTrait,
};

pub enum Item {
    Trait(ItemTrait),
    Impl(ItemImpl),
    Fn(ItemFn),
    Static(ItemStatic),
}

macro_rules! fork {
    ($fork:ident = $input:ident) => {{
        $fork = $input.fork();
        &$fork
    }};
}

impl Parse for Item {
    fn parse(input: ParseStream) -> Result<Self> {
        let attrs = input.call(Attribute::parse_outer)?;
        let mut fork;
        let item = if let Ok(mut item) = fork!(fork = input).parse::<ItemImpl>() {
            item.attrs = attrs;
            Item::Impl(item)
        } else if let Ok(mut item) = fork!(fork = input).parse::<ItemTrait>() {
            item.attrs = attrs;
            Item::Trait(item)
        } else if let Ok(mut item) = fork!(fork = input).parse::<ItemFn>() {
            item.attrs = attrs;
            Item::Fn(item)
        } else if let Ok(mut item) = fork!(fork = input).parse::<ItemStatic>() {
            item.attrs = attrs;
            Item::Static(item)
        } else {
            return Err(Error::new(Span::call_site(), "expected impl, trait or fn"));
        };
        input.advance_to(&fork);
        Ok(item)
    }
}
