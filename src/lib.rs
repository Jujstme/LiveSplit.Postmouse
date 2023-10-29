#![no_std]
#![feature(type_alias_impl_trait, const_async_blocks)]
#![warn(
    clippy::complexity,
    clippy::correctness,
    clippy::perf,
    clippy::style,
    clippy::undocumented_unsafe_blocks,
    rust_2018_idioms
)]

use asr::{
    file_format::pe,
    future::{next_tick, retry},
    signature::Signature,
    time::Duration,
    timer::{self, TimerState},
    watcher::Watcher,
    Address, Process,
};

asr::panic_handler!();
asr::async_main!(nightly);

const PROCESS_NAMES: &[&str] = &["PostMouse-Win64-Shipping.exe"];

async fn main() {
    //let settings = Settings::register();

    loop {
        // Hook to the target process
        let process = retry(|| PROCESS_NAMES.iter().find_map(|&name| Process::attach(name))).await;

        process
            .until_closes(async {
                // Once the target has been found and attached to, set up some default watchers
                let mut watchers = Watchers::default();

                // Perform memory scanning to look for the addresses we need
                let addresses = Addresses::init(&process).await;

                loop {
                    //settings.update();

                    // Splitting logic. Adapted from OG LiveSplit:
                    // Order of execution
                    // 1. update() will always be run first. There are no conditions on the execution of this action.
                    // 2. If the timer is currently either running or paused, then the isLoading, gameTime, and reset actions will be run.
                    // 3. If reset does not return true, then the split action will be run.
                    // 4. If the timer is currently not running (and not paused), then the start action will be run.
                    update_loop(&process, &addresses, &mut watchers);

                    let timer_state = timer::state();
                    if timer_state == TimerState::Running || timer_state == TimerState::Paused {
                        if let Some(is_loading) = is_loading(&watchers) {
                            match is_loading {
                                true => timer::pause_game_time(),
                                false => timer::resume_game_time(),
                            };
                        }

                        if let Some(game_time) = game_time(&watchers) {
                            timer::set_game_time(game_time)
                        }

                        match reset(&watchers) {
                            true => timer::reset(),
                            false => {
                                if split(&watchers) {
                                    timer::split()
                                }
                            }
                        };
                    }

                    if timer::state() == TimerState::NotRunning && start(&watchers) {
                        timer::start();
                        timer::pause_game_time();

                        if let Some(is_loading) = is_loading(&watchers) {
                            match is_loading {
                                true => timer::pause_game_time(),
                                false => timer::resume_game_time(),
                            };
                        }
                    }

                    next_tick().await;
                }
            })
            .await;
    }
}

#[derive(Default)]
struct Watchers {
    load_state: Watcher<bool>,
}

struct Addresses {
    g_world: Address,
}

impl Addresses {
    async fn init(process: &Process) -> Self {
        let main_module = {
            let main_module_base = retry(|| {
                PROCESS_NAMES
                    .iter()
                    .find_map(|&name| process.get_module_address(name).ok())
            })
            .await;
            let main_module_size =
                retry(|| pe::read_size_of_image(process, main_module_base)).await as u64;

            (main_module_base, main_module_size)
        };

        let ptr = {
            const SIG: Signature<15> =
                Signature::new("80 7C 24 ?? 00 ?? ?? 48 8B 3D ?? ?? ?? ?? 48");
            let ptr = retry(|| SIG.scan_process_range(process, main_module)).await + 0xA;
            ptr + 0x4 + retry(|| process.read::<i32>(ptr)).await
        };

        Self { g_world: ptr }
    }
}

fn update_loop(game: &Process, addresses: &Addresses, watchers: &mut Watchers) {
    watchers.load_state.update_infallible(
        game.read_pointer_path64::<u32>(
            addresses.g_world,
            &[0x0, 0x180, 0x38, 0x0, 0x30, 0x250, 0x350],
        )
        .unwrap_or_default()
            == 0,
    );
}

fn start(_watchers: &Watchers) -> bool {
    false
}

fn split(_watchers: &Watchers) -> bool {
    false
}

fn reset(_watchers: &Watchers) -> bool {
    false
}

fn is_loading(watchers: &Watchers) -> Option<bool> {
    Some(watchers.load_state.pair?.current)
}

fn game_time(_watchers: &Watchers) -> Option<Duration> {
    None
}
