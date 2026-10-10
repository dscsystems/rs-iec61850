//! A group member that keeps its group's keys current in an
//! [`rsession::KeyStore`].

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::task::JoinHandle;

use crate::rsession::{self, KeyStore};

use super::member::{register, MemberConfig, Registration};
use super::tek::GroupId;

/// What a [`Member`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// A registration completed.
    Registered,
    /// A TEK was added to the key store; `active` says whether it became the
    /// key sent with.
    Installed,
    /// A TEK expired, or the key server no longer lists it.
    Removed,
    /// A TEK uses algorithms the session layer does not implement.
    Skipped,
    /// A registration failed; the keys already installed stay until they
    /// expire, and the member retries.
    Failed,
}

/// A change a [`Member`] made, or a failure.
#[derive(Debug, Clone)]
pub struct Event {
    pub kind: EventKind,
    pub spi: u32,
    pub active: bool,
    pub err: Option<String>,
}

/// Receives a member's events. It must not block.
pub type EventFn = Arc<dyn Fn(&Event) + Send + Sync>;

/// Keeps the keys of one group current in an [`rsession::KeyStore`]: it
/// registers with the key server, installs each TEK when its activation delay
/// has passed, makes the most recently activated one the key a publisher
/// sends with, removes keys when they expire or when the key server stops
/// listing them, and registers again before they run out.
///
/// This member re-registers rather than taking GROUPKEY-PUSH rekeys, so a key
/// server distributing the next key with an activation delay reaches it at
/// its next registration: `refresh` has to be shorter than the time the key
/// server gives a new key before it is used.
pub struct Member {
    cfg: MemberConfig,
    group: GroupId,
    /// The longest time between registrations (5 min when zero).
    pub refresh: Duration,
    inner: Arc<Inner>,
}

struct Inner {
    store: Arc<KeyStore>,
    on_event: Mutex<Option<EventFn>>,
    keys: Mutex<HashMap<u32, InstalledKey>>,
}

struct InstalledKey {
    activates: Instant,
    expires: Option<Instant>,
    added: bool,
    active: bool,
    activation: Option<JoinHandle<()>>,
    expiry: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for Member {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Member")
            .field("group", &self.group)
            .field("refresh", &self.refresh)
            .field("keys", &self.inner.keys.lock().unwrap().keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl Member {
    /// Returns a member keeping `group`'s keys in `store`.
    pub fn new(cfg: MemberConfig, group: GroupId, store: Arc<KeyStore>) -> Member {
        Member {
            cfg,
            group,
            refresh: Duration::ZERO,
            inner: Arc::new(Inner {
                store,
                on_event: Mutex::new(None),
                keys: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Tells `f` of each change and failure.
    pub fn on_event(&self, f: impl Fn(&Event) + Send + Sync + 'static) {
        *self.inner.on_event.lock().unwrap() = Some(Arc::new(f));
    }

    /// Registers and keeps registering until `cancel` resolves. When it
    /// returns, the keys it installed are removed from the store: a member
    /// that stops following the key server does not keep using its keys.
    pub async fn run(&self, cancel: impl Future<Output = ()>) {
        let refresh = if self.refresh.is_zero() { Duration::from_secs(300) } else { self.refresh };
        let mut cancel = std::pin::pin!(cancel);
        let mut backoff = Duration::from_secs(1);
        loop {
            let wait = tokio::select! {
                _ = &mut cancel => break,
                r = register(&self.cfg, &self.group) => match r {
                    Ok(reg) => {
                        backoff = Duration::from_secs(1);
                        self.inner.event(EventKind::Registered, 0, false, None);
                        self.install(&reg);
                        next_registration(&reg, refresh)
                    }
                    Err(e) => {
                        self.inner.event(EventKind::Failed, 0, false, Some(e.to_string()));
                        let wait = backoff;
                        backoff = (2 * backoff).min(refresh.min(Duration::from_secs(60)));
                        wait
                    }
                },
            };
            tokio::select! {
                _ = &mut cancel => break,
                _ = tokio::time::sleep(wait) => {}
            }
        }
        self.inner.remove_all();
    }

    /// Puts a registration's TEKs in the store, as [`run`](Member::run) does
    /// after each registration: keys the registration no longer lists are
    /// removed, new ones are added when they activate and removed when they
    /// expire. It must be called within a tokio runtime.
    pub fn install(&self, reg: &Registration) {
        let mut keys = self.inner.keys.lock().unwrap();
        let mut listed = Vec::new();
        for t in &reg.teks {
            listed.push(t.spi);
            let rk = match t.rsession_key() {
                Ok(k) => k,
                Err(e) => {
                    self.inner.event(EventKind::Skipped, t.spi, false, Some(e.to_string()));
                    continue;
                }
            };
            let spi = t.spi;
            let ik = keys.entry(spi).or_insert_with(|| {
                let activates = reg.received + t.activation_delay;
                let inner = Arc::clone(&self.inner);
                InstalledKey {
                    activates,
                    expires: None,
                    added: false,
                    active: false,
                    activation: Some(tokio::spawn(async move {
                        tokio::time::sleep_until(activates.into()).await;
                        inner.activate(spi, rk);
                    })),
                    expiry: None,
                }
            });
            // A later registration's lifetime replaces the earlier one.
            if let Some(h) = ik.expiry.take() {
                h.abort();
            }
            ik.expires = None;
            if !t.lifetime.is_zero() {
                let expires = reg.received + t.lifetime;
                ik.expires = Some(expires);
                let inner = Arc::clone(&self.inner);
                ik.expiry = Some(tokio::spawn(async move {
                    tokio::time::sleep_until(expires.into()).await;
                    let mut keys = inner.keys.lock().unwrap();
                    inner.remove_locked(&mut keys, spi);
                }));
            }
        }
        let gone: Vec<u32> = keys.keys().copied().filter(|spi| !listed.contains(spi)).collect();
        for spi in gone {
            self.inner.remove_locked(&mut keys, spi);
        }
    }
}

impl Drop for Member {
    fn drop(&mut self) {
        for ik in self.inner.keys.lock().unwrap().values_mut() {
            if let Some(h) = ik.activation.take() {
                h.abort();
            }
            if let Some(h) = ik.expiry.take() {
                h.abort();
            }
        }
    }
}

/// When to register again: after `refresh`, or once a TEK has 10% of its
/// lifetime left, whichever comes first.
fn next_registration(reg: &Registration, refresh: Duration) -> Duration {
    reg.teks
        .iter()
        .filter(|t| !t.lifetime.is_zero())
        .map(|t| (t.lifetime * 9 / 10).max(Duration::from_secs(1)))
        .fold(refresh, Duration::min)
}

impl Inner {
    fn event(&self, kind: EventKind, spi: u32, active: bool, err: Option<String>) {
        let h = self.on_event.lock().unwrap().clone();
        if let Some(h) = h {
            h(&Event { kind, spi, active, err });
        }
    }

    fn activate(&self, spi: u32, k: rsession::Key) {
        let mut keys = self.keys.lock().unwrap();
        match keys.get_mut(&spi) {
            Some(ik) if !ik.added => {
                if let Err(e) = self.store.add(k) {
                    self.event(EventKind::Skipped, spi, false, Some(e.to_string()));
                    return;
                }
                ik.added = true;
                ik.activation = None;
            }
            _ => return,
        }
        let active = self.choose_active(&mut keys);
        self.event(EventKind::Installed, spi, active == Some(spi), None);
    }

    /// Makes the most recently activated key the one sent with, the
    /// longest-lived on a tie, and returns its SPI.
    fn choose_active(&self, keys: &mut HashMap<u32, InstalledKey>) -> Option<u32> {
        let best = keys
            .iter()
            .filter(|(_, ik)| ik.added)
            // A key that does not expire outlives any that does.
            .max_by_key(|(_, ik)| (ik.activates, ik.expires.is_none(), ik.expires))
            .map(|(spi, _)| *spi);
        for (spi, ik) in keys.iter_mut() {
            ik.active = Some(*spi) == best;
        }
        if let Some(spi) = best {
            let _ = self.store.set_active(spi);
        }
        best
    }

    fn remove_locked(&self, keys: &mut HashMap<u32, InstalledKey>, spi: u32) {
        let Some(mut ik) = keys.remove(&spi) else {
            return;
        };
        if let Some(h) = ik.activation.take() {
            h.abort();
        }
        // The expiry task may be the caller; it is not aborted from itself.
        drop(ik.expiry.take());
        if ik.added {
            self.store.remove(spi);
            self.event(EventKind::Removed, spi, false, None);
            if ik.active {
                self.choose_active(keys);
            }
        }
    }

    fn remove_all(&self) {
        let mut keys = self.keys.lock().unwrap();
        let all: Vec<u32> = keys.keys().copied().collect();
        for spi in all {
            if let Some(h) = keys.get_mut(&spi).and_then(|ik| ik.expiry.take()) {
                h.abort();
            }
            self.remove_locked(&mut keys, spi);
        }
    }
}
