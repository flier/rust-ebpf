extern crate proc_macro;

use std::iter;

use proc_macro::TokenStream;
use quote::quote;
use syn::parse_macro_input;

#[proc_macro]
pub fn license(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as syn::LitStr);
    let s = lit.value();
    let len = s.len() + 1;
    let bytes = s.bytes().chain(iter::once(0)).map(|b| quote! { #b });

    let expanded = quote! {
        #[no_mangle]
        #[link_section = "license"]
        pub static _license: [u8; #len] = [ #( #bytes ),* ];
    };

    expanded.into()
}
