#![no_std]
use asr::{signature::Signature, timer, timer::TimerState, watcher::Watcher, Address, Process};

#[cfg(all(not(test), target_arch = "wasm32"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

static AUTOSPLITTER: spinning_top::Spinlock<State> = spinning_top::const_spinlock(State {
    game: None,
    sigscans: None,
    watchers: Watchers {
        load_state: Watcher::new(),
    },
});

struct State {
    game: Option<ProcessInfo>,
    sigscans: Option<SigScan>,
    watchers: Watchers,
}

struct Watchers {
    load_state: Watcher<u8>,
}

struct ProcessInfo {
    game: Process,
    main_module_base: Address,
    //main_module_size: u64,
}

impl State {
    fn attach_process() -> Option<ProcessInfo> {
        const PROCESS_NAMES: [&str; 1] = ["PostMouse-Win64-Shipping.exe"];
        let mut proc: Option<Process> = None;
        let mut procname: &str = "";

        for name in PROCESS_NAMES {
            proc = Process::attach(name);
            if proc.is_some() {
                procname = name;
                break;
            }
        }

        let game = proc?;
        let main_module_base = game.get_module_address(procname).ok()?;

        Some(ProcessInfo {
            game,
            main_module_base,
            //main_module_size: game.get_module_size(curgamename).ok()?, // currently broken in livesplit classic
        })
    }

    fn update(&mut self) {
        // Checks is LiveSplit is currently attached to a target process and runs attach_process() otherwise
        if self.game.is_none() {
            self.game = State::attach_process()
        }
        let Some(game) = &self.game else { return };
        let proc = &game.game;

        if !proc.is_open() {
            self.game = None;
            if timer::state() == TimerState::Running { timer::pause_game_time() } // If the game crashes, game time should be paused
            return;
        };

        // Update
        // Look for valid sigscans and performs sigscan if necessary
        let Some(addresses) = &self.sigscans else { self.sigscans = SigScan::new(proc, game.main_module_base); return; };

        // Update the watchers variables
        let Some(load_state) = self.watchers.load_state.update(proc.read_pointer_path64(addresses.gworld.0, &[0x0, 0x180, 0x38, 0x0, 0x30, 0x250, 0x350]).ok()) else { return };


        // Splitting logic
        match timer::state() {
            TimerState::Running => {
                if load_state.current == 0 {
                    timer::pause_game_time()
                } else {
                    timer::resume_game_time()
                }
            }
            _ => {}
        }
    }
}

#[no_mangle]
pub extern "C" fn update() {
    AUTOSPLITTER.lock().update();
}

struct SigScan {
    gworld: Address,
}

impl SigScan {
    fn new(process: &Process, addr: Address) -> Option<Self> {
        let size = 0x4A57000; // Hack, until we can actually query ModuleMemorySize
 
        const SIG: Signature<15> = Signature::new("80 7C 24 ?? 00 ?? ?? 48 8B 3D ???????? 48");
        let mut ptr = SIG.scan_process_range(process, addr, size)?.0 + 0xA;
        ptr += 0x4 + process.read::<u32>(Address(ptr)).ok()? as u64;

        Some(Self {
            gworld: Address(ptr),
        })
    }
}