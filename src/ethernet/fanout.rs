//! One blocking interface reader per protocol subscriber.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use super::Interface;

type Callback<T> = Box<dyn FnMut(&T) + Send>;
type Slots<T> = Arc<Vec<Arc<Slot<T>>>>;

struct Slot<T> {
    stopped: AtomicBool,
    callback: Mutex<Callback<T>>,
}

pub(crate) struct Fanout<T> {
    iface: Arc<dyn Interface>,
    ether_type: u16,
    decode: fn(&[u8]) -> Option<T>,
    started: AtomicBool,
    slots: Mutex<Slots<T>>,
}

impl<T: 'static> Fanout<T> {
    pub fn new(
        iface: Arc<dyn Interface>,
        ether_type: u16,
        decode: fn(&[u8]) -> Option<T>,
    ) -> Arc<Self> {
        Arc::new(Self {
            iface,
            ether_type,
            decode,
            started: AtomicBool::new(false),
            slots: Mutex::default(),
        })
    }

    pub fn add(self: &Arc<Self>, callback: impl FnMut(&T) + Send + 'static) -> Registration<T> {
        let slot = Arc::new(Slot {
            stopped: AtomicBool::new(false),
            callback: Mutex::new(Box::new(callback)),
        });
        Arc::make_mut(&mut self.slots.lock().unwrap()).push(slot.clone());
        if !self.started.swap(true, Ordering::AcqRel) {
            let owner = Arc::downgrade(self);
            let iface = self.iface.clone();
            std::thread::spawn(move || Self::read(owner, iface));
        }
        Registration {
            owner: self.clone(),
            slot,
        }
    }

    fn read(owner: Weak<Self>, iface: Arc<dyn Interface>) {
        while let Ok(frame) = iface.read_frame() {
            let Some(owner) = owner.upgrade() else { return };
            if frame.ether_type != owner.ether_type {
                continue;
            }
            let slots = owner.slots.lock().unwrap().clone();
            if slots.is_empty() {
                continue;
            }
            let Some(message) = (owner.decode)(&frame.payload) else {
                continue;
            };
            for slot in slots.iter() {
                let mut callback = slot.callback.lock().unwrap();
                if !slot.stopped.load(Ordering::Acquire) {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        callback(&message)
                    }));
                    if result.is_err() {
                        slot.stopped.store(true, Ordering::Release);
                    }
                }
            }
        }
    }
}

impl<T> std::fmt::Debug for Fanout<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fanout")
            .field("ether_type", &self.ether_type)
            .finish_non_exhaustive()
    }
}

pub(crate) struct Registration<T> {
    owner: Arc<Fanout<T>>,
    slot: Arc<Slot<T>>,
}

impl<T> Registration<T> {
    pub fn stop(&self) {
        self.slot.stopped.store(true, Ordering::Release);
        let mut slots = self.owner.slots.lock().unwrap();
        Arc::make_mut(&mut slots).retain(|slot| !Arc::ptr_eq(slot, &self.slot));
    }

    pub fn join(&self) {
        self.stop();
        drop(self.slot.callback.lock().unwrap());
    }
}

impl<T> Drop for Registration<T> {
    fn drop(&mut self) {
        self.stop();
    }
}

impl<T> std::fmt::Debug for Registration<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registration")
            .field("stopped", &self.slot.stopped.load(Ordering::Acquire))
            .finish()
    }
}
