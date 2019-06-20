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

#[macro_export]
macro_rules! trivial {
    () => {};

    ( $(#[$outer:meta])* pub struct $name:ident ( $target:path ) ; $($rest:tt)* ) => {
        $(#[$outer])*
        #[repr(transparent)]
        #[derive(Clone, Debug)]
        pub struct $name($target);

        trivial!{ __impl_default $name }
        trivial!{ __impl_from $name, $target }
        trivial!{ __impl_into $name, $target }
        trivial!{ __impl_deref $name, $target }
        trivial!{ __impl_deref_mut $name }
        trivial!{ __impl_as_ref $name, $target }
        trivial!{ __impl_as_mut $name, $target }

        trivial!{ $($rest)* }
    };

    (__impl_default $name:ident) => {
        impl Default for $name {
            #[inline]
            fn default() -> Self {
                unsafe { mem::zeroed() }
            }
        }
    };

    (__impl_from $name:ident, $target:path) => {
        impl From<$target> for $name {
            #[inline]
            fn from(target: $target) -> Self {
                $name(target)
            }
        }
    };


    (__impl_into $name:ident, $target:path) => {
        impl Into<$target> for $name {
            #[inline]
            fn into(self) -> $target {
                self.0
            }
        }
    };

    (__impl_deref $name:ident, $target:path) => {
        impl core::ops::Deref for $name {
            type Target = $target;

            #[inline]
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
    };

    (__impl_deref_mut $name:ident) => {
        impl core::ops::DerefMut for $name {
            #[inline]
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }
    };

    (__impl_as_ref $name:ident, $target:path) => {
        impl core::convert::AsRef<$target> for $name {
            #[inline]
            fn as_ref(&self) -> & $target {
                &self.0
            }
        }
    };

    (__impl_as_mut $name:ident, $target:path) => {
        impl core::convert::AsMut<$target> for $name {
            #[inline]
            fn as_mut(&mut self) -> &mut $target {
                &mut self.0
            }
        }
    };
}
