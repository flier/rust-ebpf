use core::convert::TryFrom;

use crate::{helpers::bpf_redirect_map, Action, MapSpec};

#[inline]
pub fn redirect_map(map: &MapSpec, key: u32) -> Action {
    Action::try_from(bpf_redirect_map(map as *const _ as *const _, key, 0) as u32)
        .unwrap_or(Action::Pass)
}
