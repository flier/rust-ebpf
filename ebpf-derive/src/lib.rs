extern crate proc_macro;

use darling::{Error, FromMeta};
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, parse_quote};

#[proc_macro_derive(TryFrom)]
pub fn try_from(input: TokenStream) -> TokenStream {
    let syn::DeriveInput {
        attrs,
        ident,
        generics,
        data,
        ..
    } = parse_macro_input!(input);

    let expanded = match data {
        syn::Data::Enum(syn::DataEnum { variants, .. }) => {
            let ty = if let Some(ty) = extract_repr_ty(&attrs) {
                ty
            } else {
                return Error::custom("missing or malform #[repr(..)] attribute")
                    .with_span(&ident)
                    .write_errors()
                    .into();
            };

            let variants = variants.iter().flat_map(|var| match var {
                syn::Variant {
                    ident: varname,
                    discriminant: Some((_, repr)),
                    ..
                } => Some(quote! {
                    #repr => {
                        Ok(#ident :: #varname)
                    }
                }),
                _ => None,
            });

            let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

            quote! {
                impl #impl_generics core::convert::TryFrom<#ty> for #ident #ty_generics #where_clause {
                    type Error = #ty;

                    #[inline]
                    fn try_from(value: #ty) -> Result<Self, Self::Error> {
                        match value {
                            #( #variants , )*
                            _ => Err(value)
                        }
                    }
                }
            }
        }
        _ => unimplemented!(),
    };

    // eprintln!("expanded: {}", expanded);

    expanded.into()
}

fn extract_repr_ty<'ast>(
    attrs: impl IntoIterator<Item = &'ast syn::Attribute>,
) -> Option<syn::Ident> {
    #[derive(Default)]
    struct VisitRepr {
        ty: Option<syn::Ident>,
    }

    impl<'ast> syn::visit::Visit<'ast> for VisitRepr {
        fn visit_ident(&mut self, ident: &'ast syn::Ident) {
            self.ty = Some(ident.clone())
        }
    }

    let mut visitor = VisitRepr::default();

    for attr in attrs {
        if attr.path.is_ident("repr") {
            if let Ok(meta) = attr.parse_meta() {
                syn::visit::visit_meta(&mut visitor, &meta);
            }
        }
    }

    visitor.ty
}

#[proc_macro]
pub fn license(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as syn::LitStr);
    let s = lit.value();
    let len = s.len() + 1;
    let bytes = s.bytes().chain(std::iter::once(0)).map(|b| quote! { #b });

    let expanded = quote! {
        #[no_mangle]
        #[link_section = "license"]
        pub static _license: [u8; #len] = [ #( #bytes ),* ];
    };

    expanded.into()
}

#[derive(Debug, FromMeta)]
struct ProgramArgs {
    name: String,
}

#[proc_macro_attribute]
pub fn program(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as syn::AttributeArgs);
    let mut func = parse_macro_input!(input as syn::ItemFn);

    match func {
        syn::ItemFn {
            vis: syn::Visibility::Public(_),
            constness: None,
            asyncness: None,
            unsafety: Some(_),
            abi:
                Some(syn::Abi {
                    name: Some(ref abi),
                    ..
                }),
            ..
        } if abi.value() == "C" => {
            let ProgramArgs { name } = match ProgramArgs::from_list(&args) {
                Ok(v) => v,
                Err(e) => {
                    return e.write_errors().into();
                }
            };

            func.attrs.push(parse_quote! { #[no_mangle] });
            func.attrs.push(parse_quote! { #[link_section = #name] });

            let expanded = quote! { #func };

            expanded.into()
        }
        _ => {
            let ident = &func.ident;
            let inputs = &func.decl.inputs;
            let output = &func.decl.output;
            let sig = quote! { pub unsafe extern "C" fn #ident(#(#inputs),*) #output { ... } };

            Error::custom(format!(
                "eBPF program signature should be `{}`",
                sig.to_string()
            ))
            .with_span(&func.ident)
            .write_errors()
            .into()
        }
    }
}
