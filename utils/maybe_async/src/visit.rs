//! This file was heavily inspired by [`visit.rs`](https://github.com/fMeow/maybe-async-rs/blob/b32a81704f6d84576d77e06882a06570e7f38de9/src/visit.rs).

use proc_macro2::TokenStream;
use quote::quote;
use syn::{
    visit_mut::{self, VisitMut},
    Expr, ExprBlock, File, Stmt,
};

pub struct AsyncAwaitRemoval;

impl AsyncAwaitRemoval {
    pub fn remove_async_await(&mut self, item: TokenStream) -> TokenStream {
        let mut syntax_tree: File = syn::parse(item.into()).unwrap();
        self.visit_file_mut(&mut syntax_tree);
        quote!(#syntax_tree)
    }
}

impl VisitMut for AsyncAwaitRemoval {
    fn visit_expr_mut(&mut self, node: &mut Expr) {
        // Delegate to the default impl to visit nested expressions.
        visit_mut::visit_expr_mut(self, node);

        match node {
            Expr::Await(expr) => *node = (*expr.base).clone(),

            Expr::Async(expr) => {
                let inner = &expr.block;
                let sync_expr = if let [Stmt::Expr(expr, None)] = inner.stmts.as_slice() {
                    // remove useless braces when there is only one statement
                    expr.clone()
                } else {
                    Expr::Block(ExprBlock {
                        attrs: expr.attrs.clone(),
                        block: inner.clone(),
                        label: None,
                    })
                };
                *node = sync_expr;
            }
            _ => {}
        }
    }
}
