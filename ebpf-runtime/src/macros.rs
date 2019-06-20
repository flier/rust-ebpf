#[macro_export]
macro_rules! version {
    ($version:literal) => {
        #[no_mangle]
        #[link_section = "version"]
        pub static _version: u32 = $version;
    };
}

#[macro_export]
macro_rules! map {
    () => {};
    ( $name:ident : $ty:ident { [ $key:ty ] $value:ty ; $capacity:expr } $($rest:tt)* ) => {
        #[no_mangle]
        #[link_section = "maps"]
        pub static $name: $crate::MapSpec = $crate::MapSpec {
            ty: $crate::MapType::$ty,
            key_size: core::mem::size_of::<$key>() as u32,
            value_size: core::mem::size_of::<$value>() as u32,
            capacity: $capacity,
            flags: $crate::MapFlags::empty(),
        };

        map!{ $($rest)* }
    };
}
